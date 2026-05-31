// Request rules: YAML-configured include/exclude/rewrite rules applied to log entries during parsing.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use rand::Rng as _;
use regex::Regex;
use serde::Deserialize;

use crate::parser::LogEntry;

// ── Raw config types (YAML deserialization) ────────────────────────────────

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct RawRule {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub when: RawWhen,
    pub action: RawAction,
}

/// `when` can be written three ways:
///   - a plain list → implicit `all`
///   - `{all: [...]}`
///   - `{any: [...]}`
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum RawWhen {
    List(Vec<RawCondition>),
    All { all: Vec<RawCondition> },
    Any { any: Vec<RawCondition> },
}

#[derive(Debug, Deserialize)]
pub struct RawCondition {
    pub field: String,
    pub op: String,
    /// Scalar for most ops; sequence for `in` / `not_in`.
    pub value: serde_yaml::Value,
}

#[derive(Debug)]
pub enum RawAction {
    Ignore,
    /// List of top-N table names to exclude from: urls, hosts, refs, agents, countries.
    Hide(Vec<String>),
    /// Keep only this fraction of matching entries (0.0 = drop all, 1.0 = keep all).
    Sample(f64),
    /// Assign a named bucket to the entry for per-bucket stats tracking.
    Bucket(String),
}

impl<'de> serde::Deserialize<'de> for RawAction {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::{self, MapAccess, Visitor};

        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = RawAction;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, r#""ignore" or {{hide: [tables]}} or {{sample: 0.x}} or {{bucket: name}}"#)
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<RawAction, E> {
                match v {
                    "ignore" => Ok(RawAction::Ignore),
                    other => Err(E::unknown_variant(other, &["ignore", "hide", "sample", "bucket"])),
                }
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<RawAction, M::Error> {
                let key: String = map
                    .next_key()?
                    .ok_or_else(|| de::Error::missing_field("key"))?;
                match key.as_str() {
                    "hide" => Ok(RawAction::Hide(map.next_value()?)),
                    "sample" => Ok(RawAction::Sample(map.next_value()?)),
                    "bucket" => Ok(RawAction::Bucket(map.next_value()?)),
                    other => Err(de::Error::unknown_field(other, &["hide", "sample", "bucket"])),
                }
            }
        }
        d.deserialize_any(V)
    }
}

// ── Compiled types ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Ip,
    Method,
    Url,
    Referer,
    UserAgent,
    Proto,
    Status,
    Bytes,
    ResponseTime,
    /// The bucket name assigned by a preceding rule in the same pass.
    /// Valid ops: eq, neq, in, not_in only.
    Bucket,
}

#[derive(Debug)]
pub enum Condition {
    // String ops
    Eq {
        field: Field,
        value: String,
    },
    Neq {
        field: Field,
        value: String,
    },
    StartsWith {
        field: Field,
        prefix: String,
    },
    EndsWith {
        field: Field,
        suffix: String,
    },
    Contains {
        field: Field,
        needle: String,
    },
    Matches {
        field: Field,
        pattern: Regex,
    },
    In {
        field: Field,
        values: HashSet<String>,
    },
    NotIn {
        field: Field,
        values: HashSet<String>,
    },
    // Length ops (string fields only, not Bucket)
    LenGt {
        field: Field,
        value: usize,
    },
    LenLt {
        field: Field,
        value: usize,
    },
    LenGte {
        field: Field,
        value: usize,
    },
    LenLte {
        field: Field,
        value: usize,
    },
    LenEq {
        field: Field,
        value: usize,
    },
    LenBetween {
        field: Field,
        low: usize,
        high: usize,
    },
    // Numeric ops
    NumEq {
        field: Field,
        value: u64,
    },
    NumNeq {
        field: Field,
        value: u64,
    },
    Gt {
        field: Field,
        value: u64,
    },
    Lt {
        field: Field,
        value: u64,
    },
    Gte {
        field: Field,
        value: u64,
    },
    Lte {
        field: Field,
        value: u64,
    },
    Between {
        field: Field,
        low: u64,
        high: u64,
    },
    NumIn {
        field: Field,
        values: HashSet<u64>,
    },
    NumNotIn {
        field: Field,
        values: HashSet<u64>,
    },
}

pub enum MatchMode {
    All,
    Any,
}

/// Bitmask of top-N tables a `hide` action excludes an entry from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HideMask(u8);

impl HideMask {
    pub const NONE: HideMask = HideMask(0);
    pub const TOP_URLS: HideMask = HideMask(1 << 0);
    pub const TOP_HOSTS: HideMask = HideMask(1 << 1);
    pub const TOP_REFS: HideMask = HideMask(1 << 2);
    pub const TOP_AGENTS: HideMask = HideMask(1 << 3);
    pub const TOP_COUNTRIES: HideMask = HideMask(1 << 4);
    pub const TIMING: HideMask = HideMask(1 << 5);

    fn with(self, other: HideMask) -> HideMask {
        HideMask(self.0 | other.0)
    }

    pub fn contains(self, other: HideMask) -> bool {
        (self.0 & other.0) != 0
    }
}

impl std::ops::BitOrAssign for HideMask {
    fn bitor_assign(&mut self, other: HideMask) {
        self.0 |= other.0;
    }
}

#[derive(Debug)]
pub enum Action {
    Ignore,
    /// Count hits/visits/unique IPs but exclude the named top-N tables.
    Hide(HideMask),
    /// Probabilistically drop matching entries; keep fraction is 0.0–1.0.
    Sample(f64),
    /// Assign a named bucket to the entry for per-bucket stats tracking.
    Bucket(Arc<str>),
}

pub struct Rule {
    pub name: Arc<str>,
    pub mode: MatchMode,
    pub conditions: Vec<Condition>,
    pub action: Action,
    /// Fires a warning log line the first time a Bucket action is skipped
    /// because the entry is already bucketed.  AtomicBool gives warn-once
    /// semantics without a mutex.
    bucket_shadow_warned: AtomicBool,
}

/// The per-rule effect recorded when apply() processes a matched rule.
pub enum MatchEffect {
    /// Rule dropped the entry (Ignore action or Sample that dropped).
    Ignored,
    /// Rule applied a Hide mask.
    Hidden,
    /// Rule assigned a bucket to the entry.
    Bucketed,
}

/// Accumulated result of evaluating all rules against a single log entry.
pub struct MatchedRules<'a> {
    /// The bucket assigned by the first matching Bucket action, if any.
    pub bucket: Option<&'a Arc<str>>,
    /// Combined HideMask from all matching Hide actions.
    pub hide: HideMask,
    /// True if any Ignore action fired — entry should be dropped.
    pub ignored: bool,
    /// True if a Sample action dropped the entry — entry should be dropped.
    pub sampled: bool,
    /// Per-rule effects for updating RuleStats counters.
    pub effects: Vec<(&'a Arc<str>, MatchEffect)>,
}

/// An opaque black box: put a log entry in, get an optional action back.
pub struct RuleSet(Vec<Rule>);

// ── Slug helpers ───────────────────────────────────────────────────────────

/// Derive a filesystem-safe slug from a bucket name.
/// Lowercases, replaces non-alphanumeric chars with `-`, collapses runs.
pub(crate) fn make_slug(name: &str) -> String {
    let lowered: String = name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    lowered
        .split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

// ── Compilation ────────────────────────────────────────────────────────────

impl Field {
    fn is_numeric(self) -> bool {
        matches!(self, Field::Status | Field::Bytes | Field::ResponseTime)
    }
}

fn parse_field(s: &str) -> Result<Field> {
    match s {
        "ip" => Ok(Field::Ip),
        "method" => Ok(Field::Method),
        "url" => Ok(Field::Url),
        "referer" => Ok(Field::Referer),
        "user_agent" => Ok(Field::UserAgent),
        "proto" => Ok(Field::Proto),
        "status" => Ok(Field::Status),
        "bytes" => Ok(Field::Bytes),
        "response_time" => Ok(Field::ResponseTime),
        "bucket" => Ok(Field::Bucket),
        other => bail!("unknown field '{other}'"),
    }
}

fn yaml_as_u64(v: &serde_yaml::Value, ctx: &str) -> Result<u64> {
    match v {
        serde_yaml::Value::Number(n) => n
            .as_u64()
            .with_context(|| format!("{ctx}: value must be a non-negative integer")),
        _ => bail!("{ctx}: value must be a number"),
    }
}

fn yaml_as_usize(v: &serde_yaml::Value, ctx: &str) -> Result<usize> {
    yaml_as_u64(v, ctx).map(|n| n as usize)
}

fn yaml_as_str(v: &serde_yaml::Value, ctx: &str) -> Result<String> {
    match v {
        serde_yaml::Value::String(s) => Ok(s.clone()),
        serde_yaml::Value::Number(n) => Ok(n.to_string()),
        serde_yaml::Value::Bool(b) => Ok(b.to_string()),
        _ => bail!("{ctx}: value must be a string"),
    }
}

fn yaml_as_str_list(v: &serde_yaml::Value, ctx: &str) -> Result<HashSet<String>> {
    match v {
        serde_yaml::Value::Sequence(seq) => seq.iter().map(|item| yaml_as_str(item, ctx)).collect(),
        _ => bail!("{ctx}: value must be a list for 'in'/'not_in'"),
    }
}

fn yaml_as_u64_list(v: &serde_yaml::Value, ctx: &str) -> Result<HashSet<u64>> {
    match v {
        serde_yaml::Value::Sequence(seq) => seq.iter().map(|item| yaml_as_u64(item, ctx)).collect(),
        _ => bail!("{ctx}: value must be a list for 'in'/'not_in'"),
    }
}

fn compile_condition(raw: &RawCondition, rule_name: &str) -> Result<Condition> {
    let ctx = format!(
        "rule '{}', field '{}', op '{}'",
        rule_name, raw.field, raw.op
    );
    let field = parse_field(&raw.field).with_context(|| ctx.clone())?;
    let op = raw.op.as_str();

    // Bucket field: only eq/neq/in/not_in are valid.
    if field == Field::Bucket {
        return match op {
            "eq" => Ok(Condition::Eq {
                field,
                value: yaml_as_str(&raw.value, &ctx)?,
            }),
            "neq" => Ok(Condition::Neq {
                field,
                value: yaml_as_str(&raw.value, &ctx)?,
            }),
            "in" => Ok(Condition::In {
                field,
                values: yaml_as_str_list(&raw.value, &ctx)?,
            }),
            "not_in" => Ok(Condition::NotIn {
                field,
                values: yaml_as_str_list(&raw.value, &ctx)?,
            }),
            other => bail!(
                "{ctx}: field 'bucket' only supports eq/neq/in/not_in, got '{other}'"
            ),
        };
    }

    // Numeric-only ops
    if field.is_numeric() {
        return match op {
            "eq" => Ok(Condition::NumEq {
                field,
                value: yaml_as_u64(&raw.value, &ctx)?,
            }),
            "neq" => Ok(Condition::NumNeq {
                field,
                value: yaml_as_u64(&raw.value, &ctx)?,
            }),
            "gt" => Ok(Condition::Gt {
                field,
                value: yaml_as_u64(&raw.value, &ctx)?,
            }),
            "lt" => Ok(Condition::Lt {
                field,
                value: yaml_as_u64(&raw.value, &ctx)?,
            }),
            "gte" => Ok(Condition::Gte {
                field,
                value: yaml_as_u64(&raw.value, &ctx)?,
            }),
            "lte" => Ok(Condition::Lte {
                field,
                value: yaml_as_u64(&raw.value, &ctx)?,
            }),
            "between" => match &raw.value {
                serde_yaml::Value::Sequence(seq) if seq.len() == 2 => {
                    let low = yaml_as_u64(&seq[0], &ctx)?;
                    let high = yaml_as_u64(&seq[1], &ctx)?;
                    if low > high {
                        bail!("{ctx}: 'between' low ({low}) must be <= high ({high})");
                    }
                    Ok(Condition::Between { field, low, high })
                }
                _ => bail!("{ctx}: 'between' requires [low, high]"),
            },
            "in" => {
                let values = yaml_as_u64_list(&raw.value, &ctx)?;
                Ok(Condition::NumIn { field, values })
            }
            "not_in" => {
                let values = yaml_as_u64_list(&raw.value, &ctx)?;
                Ok(Condition::NumNotIn { field, values })
            }
            other => bail!("{ctx}: unknown op '{other}' for numeric field"),
        };
    }

    // String ops
    match op {
        "eq" => Ok(Condition::Eq {
            field,
            value: yaml_as_str(&raw.value, &ctx)?,
        }),
        "neq" => Ok(Condition::Neq {
            field,
            value: yaml_as_str(&raw.value, &ctx)?,
        }),
        "starts_with" => Ok(Condition::StartsWith {
            field,
            prefix: yaml_as_str(&raw.value, &ctx)?,
        }),
        "ends_with" => Ok(Condition::EndsWith {
            field,
            suffix: yaml_as_str(&raw.value, &ctx)?,
        }),
        "contains" => Ok(Condition::Contains {
            field,
            needle: yaml_as_str(&raw.value, &ctx)?,
        }),
        "matches" => {
            let pat = yaml_as_str(&raw.value, &ctx)?;
            let re = Regex::new(&pat).with_context(|| format!("{ctx}: invalid regex '{pat}'"))?;
            Ok(Condition::Matches { field, pattern: re })
        }
        "in" => Ok(Condition::In {
            field,
            values: yaml_as_str_list(&raw.value, &ctx)?,
        }),
        "not_in" => Ok(Condition::NotIn {
            field,
            values: yaml_as_str_list(&raw.value, &ctx)?,
        }),
        "len_gt" => Ok(Condition::LenGt {
            field,
            value: yaml_as_usize(&raw.value, &ctx)?,
        }),
        "len_lt" => Ok(Condition::LenLt {
            field,
            value: yaml_as_usize(&raw.value, &ctx)?,
        }),
        "len_gte" => Ok(Condition::LenGte {
            field,
            value: yaml_as_usize(&raw.value, &ctx)?,
        }),
        "len_lte" => Ok(Condition::LenLte {
            field,
            value: yaml_as_usize(&raw.value, &ctx)?,
        }),
        "len_eq" => Ok(Condition::LenEq {
            field,
            value: yaml_as_usize(&raw.value, &ctx)?,
        }),
        "len_between" => match &raw.value {
            serde_yaml::Value::Sequence(seq) if seq.len() == 2 => {
                let low = yaml_as_usize(&seq[0], &ctx)?;
                let high = yaml_as_usize(&seq[1], &ctx)?;
                if low > high {
                    bail!("{ctx}: 'len_between' low ({low}) must be <= high ({high})");
                }
                Ok(Condition::LenBetween { field, low, high })
            }
            _ => bail!("{ctx}: 'len_between' requires [low, high]"),
        },
        other => bail!("{ctx}: unknown op '{other}'"),
    }
}

fn parse_hide_mask(tables: &[String], rule_name: &str) -> Result<HideMask> {
    let mut mask = HideMask::NONE;
    for t in tables {
        mask = match t.as_str() {
            "top_urls" => mask.with(HideMask::TOP_URLS),
            "top_hosts" => mask.with(HideMask::TOP_HOSTS),
            "top_refs" => mask.with(HideMask::TOP_REFS),
            "top_agents" => mask.with(HideMask::TOP_AGENTS),
            "top_countries" => mask.with(HideMask::TOP_COUNTRIES),
            "timing" => mask.with(HideMask::TIMING),
            other => bail!("rule '{rule_name}': unknown hide target '{other}'"),
        };
    }
    Ok(mask)
}

fn validate_bucket_name(name: &str, rule_name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("rule '{rule_name}': bucket name must not be empty");
    }
    if name.contains('/') || name.contains('\\') {
        bail!("rule '{rule_name}': bucket name must not contain '/' or '\\'");
    }
    Ok(())
}

fn compile_rule(raw: &RawRule) -> Result<Rule> {
    let (mode, raw_conditions) = match &raw.when {
        RawWhen::List(c) | RawWhen::All { all: c } => (MatchMode::All, c),
        RawWhen::Any { any: c } => (MatchMode::Any, c),
    };

    let conditions = raw_conditions
        .iter()
        .map(|c| compile_condition(c, &raw.name))
        .collect::<Result<Vec<_>>>()?;

    if conditions.is_empty() {
        bail!(
            "rule '{}': 'when' must contain at least one condition",
            raw.name
        );
    }

    let action = match &raw.action {
        RawAction::Ignore => Action::Ignore,
        RawAction::Hide(tables) => Action::Hide(parse_hide_mask(tables, &raw.name)?),
        RawAction::Sample(rate) => {
            if !(*rate >= 0.0 && *rate <= 1.0) {
                bail!(
                    "rule '{}': sample rate must be between 0.0 and 1.0, got {}",
                    raw.name,
                    rate
                );
            }
            Action::Sample(*rate)
        }
        RawAction::Bucket(name) => {
            validate_bucket_name(name, &raw.name)?;
            Action::Bucket(name.as_str().into())
        }
    };

    Ok(Rule {
        name: raw.name.as_str().into(),
        mode,
        conditions,
        action,
        bucket_shadow_warned: AtomicBool::new(false),
    })
}

impl RuleSet {
    pub fn compile(raw: &[RawRule]) -> Result<Self> {
        let rules = raw
            .iter()
            .filter(|r| r.enabled)
            .map(compile_rule)
            .collect::<Result<Vec<_>>>()?;

        // Validate bucket slug uniqueness across all bucket actions.
        let mut seen: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        for rule in &rules {
            if let Action::Bucket(name) = &rule.action {
                let slug = make_slug(name);
                if slug.is_empty() {
                    bail!(
                        "rule '{}': bucket name '{}' produces an empty slug after sanitisation",
                        rule.name,
                        name
                    );
                }
                if let Some(other) = seen.get(&slug) {
                    bail!(
                        "buckets '{}' and '{}' both produce the slug '{}' — rename one",
                        name,
                        other,
                        slug
                    );
                }
                seen.insert(slug, name.as_ref().to_string());
            }
        }

        Ok(Self(rules))
    }

    /// Evaluate all rules against `entry` with fall-through semantics.
    /// All matching rules apply in order; `Ignore` and dropped `Sample` short-circuit.
    /// Returns `None` if no rule matched.
    pub fn apply(&self, entry: &LogEntry) -> Option<MatchedRules<'_>> {
        let mut result = MatchedRules {
            bucket: None,
            hide: HideMask::NONE,
            ignored: false,
            sampled: false,
            effects: Vec::new(),
        };
        let mut current_bucket: Option<&Arc<str>> = None;
        let mut any_match = false;

        for rule in &self.0 {
            if rule.matches(entry, current_bucket.map(|b| b.as_ref())) {
                any_match = true;
                match &rule.action {
                    Action::Ignore => {
                        result.effects.push((&rule.name, MatchEffect::Ignored));
                        result.ignored = true;
                        break;
                    }
                    Action::Hide(mask) => {
                        result.effects.push((&rule.name, MatchEffect::Hidden));
                        result.hide |= *mask;
                    }
                    Action::Bucket(name) => {
                        if current_bucket.is_none() {
                            current_bucket = Some(name);
                            result.bucket = Some(name);
                            result.effects.push((&rule.name, MatchEffect::Bucketed));
                        } else {
                            // Warn once per rule per run when a bucket is shadowed.
                            if !rule.bucket_shadow_warned.swap(true, Ordering::Relaxed) {
                                crate::logging::log(&format!(
                                    "warning: rule '{}' bucket '{}' was skipped because \
                                     entry was already bucketed as '{}' — use \
                                     'field: bucket, op: neq' to prevent this",
                                    rule.name,
                                    name,
                                    current_bucket.unwrap().as_ref(),
                                ));
                            }
                        }
                    }
                    Action::Sample(rate) => {
                        if rand::thread_rng().gen::<f64>() >= *rate {
                            result.effects.push((&rule.name, MatchEffect::Ignored));
                            result.sampled = true;
                            break;
                        }
                        // Kept by sample — no visible effect, continue evaluating.
                    }
                }
            }
        }

        if any_match { Some(result) } else { None }
    }
}

// ── Evaluation ─────────────────────────────────────────────────────────────

impl LogEntry {
    #[inline]
    fn rule_str(&self, field: Field) -> &str {
        match field {
            Field::Ip => self.ip(),
            Field::Method => self.method(),
            Field::Url => self.path(),
            Field::Referer => self.referer(),
            Field::UserAgent => self.user_agent(),
            Field::Proto => self.proto(),
            Field::Status | Field::Bytes | Field::ResponseTime | Field::Bucket => "",
        }
    }

    #[inline]
    fn rule_num(&self, field: Field) -> Option<u64> {
        match field {
            Field::Status => Some(self.status as u64),
            Field::Bytes => Some(self.bytes),
            Field::ResponseTime => self.upstream_response_time_ms.map(|v| v as u64),
            _ => None,
        }
    }
}

/// Return the string value for a field, taking `current_bucket` for `Field::Bucket`.
#[inline]
fn field_str<'e>(entry: &'e LogEntry, field: Field, current_bucket: Option<&'e str>) -> &'e str {
    if field == Field::Bucket {
        current_bucket.unwrap_or("")
    } else {
        entry.rule_str(field)
    }
}

impl Condition {
    #[inline]
    pub fn matches(&self, entry: &LogEntry, current_bucket: Option<&str>) -> bool {
        match self {
            Condition::Eq { field, value } => {
                field_str(entry, *field, current_bucket) == value.as_str()
            }
            Condition::Neq { field, value } => {
                field_str(entry, *field, current_bucket) != value.as_str()
            }
            Condition::StartsWith { field, prefix } => {
                field_str(entry, *field, current_bucket).starts_with(prefix.as_str())
            }
            Condition::EndsWith { field, suffix } => {
                field_str(entry, *field, current_bucket).ends_with(suffix.as_str())
            }
            Condition::Contains { field, needle } => {
                field_str(entry, *field, current_bucket).contains(needle.as_str())
            }
            Condition::Matches { field, pattern } => {
                pattern.is_match(field_str(entry, *field, current_bucket))
            }
            Condition::In { field, values } => {
                values.contains(field_str(entry, *field, current_bucket))
            }
            Condition::NotIn { field, values } => {
                !values.contains(field_str(entry, *field, current_bucket))
            }
            // Length ops are not valid for Field::Bucket (enforced at compile time).
            Condition::LenGt { field, value } => entry.rule_str(*field).len() > *value,
            Condition::LenLt { field, value } => entry.rule_str(*field).len() < *value,
            Condition::LenGte { field, value } => entry.rule_str(*field).len() >= *value,
            Condition::LenLte { field, value } => entry.rule_str(*field).len() <= *value,
            Condition::LenEq { field, value } => entry.rule_str(*field).len() == *value,
            Condition::LenBetween { field, low, high } => {
                let n = entry.rule_str(*field).len();
                n >= *low && n <= *high
            }
            Condition::NumEq { field, value } => {
                entry.rule_num(*field).map_or(false, |v| v == *value)
            }
            Condition::NumNeq { field, value } => {
                entry.rule_num(*field).map_or(false, |v| v != *value)
            }
            Condition::Gt { field, value } => {
                entry.rule_num(*field).map_or(false, |v| v > *value)
            }
            Condition::Lt { field, value } => {
                entry.rule_num(*field).map_or(false, |v| v < *value)
            }
            Condition::Gte { field, value } => {
                entry.rule_num(*field).map_or(false, |v| v >= *value)
            }
            Condition::Lte { field, value } => {
                entry.rule_num(*field).map_or(false, |v| v <= *value)
            }
            Condition::Between { field, low, high } => {
                entry.rule_num(*field).map_or(false, |v| v >= *low && v <= *high)
            }
            Condition::NumIn { field, values } => {
                entry.rule_num(*field).map_or(false, |v| values.contains(&v))
            }
            Condition::NumNotIn { field, values } => {
                entry.rule_num(*field).map_or(false, |v| !values.contains(&v))
            }
        }
    }
}

impl Rule {
    #[inline]
    pub fn matches(&self, entry: &LogEntry, current_bucket: Option<&str>) -> bool {
        match self.mode {
            MatchMode::All => self.conditions.iter().all(|c| c.matches(entry, current_bucket)),
            MatchMode::Any => self.conditions.iter().any(|c| c.matches(entry, current_bucket)),
        }
    }
}

/// Wraps a compiled `RuleSet` in an `Arc` for cheap cloning into threads.
pub type SharedRuleSet = Arc<RuleSet>;

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn make_entry(line: &str) -> LogEntry {
        crate::parser::combined::parse_line(line.to_string()).expect("test entry must parse")
    }

    fn single(field: &str, op: &str, value: serde_yaml::Value) -> RuleSet {
        RuleSet::compile(&[RawRule {
            name: "t".into(),
            enabled: true,
            when: RawWhen::List(vec![RawCondition {
                field: field.into(),
                op: op.into(),
                value,
            }]),
            action: RawAction::Ignore,
        }])
        .expect("compile")
    }

    fn num(n: u64) -> serde_yaml::Value {
        serde_yaml::Value::Number(n.into())
    }

    fn str_val(s: &str) -> serde_yaml::Value {
        serde_yaml::Value::String(s.into())
    }

    fn seq(items: &[&str]) -> serde_yaml::Value {
        serde_yaml::Value::Sequence(items.iter().map(|s| str_val(s)).collect())
    }

    fn num_seq(items: &[u64]) -> serde_yaml::Value {
        serde_yaml::Value::Sequence(items.iter().map(|n| num(*n)).collect())
    }

    fn is_ignored(rs: &RuleSet, entry: &LogEntry) -> bool {
        rs.apply(entry).map_or(false, |m| m.ignored || m.sampled)
    }

    fn applied_hide(rs: &RuleSet, entry: &LogEntry) -> Option<HideMask> {
        rs.apply(entry).map(|m| m.hide)
    }

    fn applied_bucket(rs: &RuleSet, entry: &LogEntry) -> Option<String> {
        rs.apply(entry)
            .and_then(|m| m.bucket.map(|b| b.as_ref().to_string()))
    }

    // Log lines covering several field combinations
    // status=200, bytes=1234, url=/static/foo.js, ua=Mozilla/5.0, ip=1.2.3.4
    const A: &str = r#"1.2.3.4 - - [10/May/2024:12:00:00 +0000] "GET /static/foo.js HTTP/1.1" 200 1234 "https://example.com/" "Mozilla/5.0""#;
    // status=301, bytes=0, url=/old/page, ua=Googlebot/2.1, ip=5.6.7.8
    const B: &str = r#"5.6.7.8 - - [10/May/2024:13:00:00 +0000] "GET /old/page HTTP/1.1" 301 0 "-" "Googlebot/2.1""#;
    // status=404, bytes=512, url=/missing, ua=curl/7.81.0, ip=10.0.0.1
    const C: &str = r#"10.0.0.1 - - [10/May/2024:14:00:00 +0000] "POST /missing HTTP/2.0" 404 512 "-" "curl/7.81.0""#;
    // status=200, bytes=100, url=/, response_time=2500ms (us=2.5)
    const RT: &str = r#"1.2.3.4 - - [10/May/2024:15:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "-" us=2.5"#;

    // ── String ops ────────────────────────────────────────────────────────────

    #[test]
    fn string_eq_match() {
        let rs = single("method", "eq", str_val("GET"));
        assert!(is_ignored(&rs, &make_entry(A)));
        assert!(!is_ignored(&rs, &make_entry(C))); // POST
    }

    #[test]
    fn string_neq() {
        let rs = single("method", "neq", str_val("GET"));
        assert!(!is_ignored(&rs, &make_entry(A)));
        assert!(is_ignored(&rs, &make_entry(C))); // POST != GET
    }

    #[test]
    fn starts_with_match_and_miss() {
        let rs = single("url", "starts_with", str_val("/static/"));
        assert!(is_ignored(&rs, &make_entry(A)));
        assert!(!is_ignored(&rs, &make_entry(B)));
    }

    #[test]
    fn ends_with_match_and_miss() {
        let rs = single("url", "ends_with", str_val(".js"));
        assert!(is_ignored(&rs, &make_entry(A)));
        assert!(!is_ignored(&rs, &make_entry(B)));
    }

    #[test]
    fn contains_user_agent() {
        let rs = single("user_agent", "contains", str_val("Googlebot"));
        assert!(!is_ignored(&rs, &make_entry(A)));
        assert!(is_ignored(&rs, &make_entry(B)));
    }

    #[test]
    fn matches_regex() {
        let rs = single("url", "matches", str_val(r"^/static/.*\.js$"));
        assert!(is_ignored(&rs, &make_entry(A)));
        assert!(!is_ignored(&rs, &make_entry(B)));
    }

    #[test]
    fn in_set_string() {
        let rs = single("user_agent", "in", seq(&["curl/7.81.0", "wget/1.0"]));
        assert!(!is_ignored(&rs, &make_entry(A)));
        assert!(is_ignored(&rs, &make_entry(C)));
    }

    #[test]
    fn not_in_set_string() {
        let rs = single("user_agent", "not_in", seq(&["curl/7.81.0", "wget/1.0"]));
        assert!(is_ignored(&rs, &make_entry(A)));
        assert!(!is_ignored(&rs, &make_entry(C)));
    }

    #[test]
    fn ip_field() {
        let rs = single("ip", "eq", str_val("10.0.0.1"));
        assert!(!is_ignored(&rs, &make_entry(A)));
        assert!(is_ignored(&rs, &make_entry(C)));
    }

    #[test]
    fn referer_field() {
        let rs = single("referer", "contains", str_val("example.com"));
        assert!(is_ignored(&rs, &make_entry(A)));
        assert!(!is_ignored(&rs, &make_entry(B))); // referer is "-"
    }

    #[test]
    fn proto_field() {
        let rs = single("proto", "eq", str_val("HTTP/2.0"));
        assert!(!is_ignored(&rs, &make_entry(A)));
        assert!(is_ignored(&rs, &make_entry(C)));
    }

    // ── Numeric ops ───────────────────────────────────────────────────────────

    #[test]
    fn num_eq_status() {
        let rs = single("status", "eq", num(200));
        assert!(is_ignored(&rs, &make_entry(A)));
        assert!(!is_ignored(&rs, &make_entry(B)));
    }

    #[test]
    fn num_neq_status() {
        let rs = single("status", "neq", num(200));
        assert!(!is_ignored(&rs, &make_entry(A)));
        assert!(is_ignored(&rs, &make_entry(B)));
    }

    #[test]
    fn num_gt() {
        let rs = single("status", "gt", num(300));
        assert!(!is_ignored(&rs, &make_entry(A))); // 200 not > 300
        assert!(is_ignored(&rs, &make_entry(B))); // 301 > 300
        assert!(is_ignored(&rs, &make_entry(C))); // 404 > 300
    }

    #[test]
    fn num_lt() {
        let rs = single("status", "lt", num(300));
        assert!(is_ignored(&rs, &make_entry(A))); // 200 < 300
        assert!(!is_ignored(&rs, &make_entry(B))); // 301 not < 300
    }

    #[test]
    fn num_gte_boundary() {
        let rs = single("status", "gte", num(301));
        assert!(!is_ignored(&rs, &make_entry(A))); // 200
        assert!(is_ignored(&rs, &make_entry(B))); // 301 == 301
        assert!(is_ignored(&rs, &make_entry(C))); // 404 > 301
    }

    #[test]
    fn num_lte_boundary() {
        let rs = single("status", "lte", num(301));
        assert!(is_ignored(&rs, &make_entry(A))); // 200 <= 301
        assert!(is_ignored(&rs, &make_entry(B))); // 301 == 301
        assert!(!is_ignored(&rs, &make_entry(C))); // 404 > 301
    }

    #[test]
    fn num_between_inclusive_boundaries() {
        let rs = single("status", "between", num_seq(&[300, 399]));
        assert!(!is_ignored(&rs, &make_entry(A))); // 200
        assert!(is_ignored(&rs, &make_entry(B))); // 301 in [300,399]
        assert!(!is_ignored(&rs, &make_entry(C))); // 404
    }

    #[test]
    fn num_between_exact_boundaries() {
        let rs = single("status", "between", num_seq(&[301, 301]));
        assert!(is_ignored(&rs, &make_entry(B)));
        assert!(!is_ignored(&rs, &make_entry(A)));
    }

    #[test]
    fn bytes_field() {
        let rs = single("bytes", "gt", num(1000));
        assert!(is_ignored(&rs, &make_entry(A))); // 1234
        assert!(!is_ignored(&rs, &make_entry(B))); // 0
    }

    #[test]
    fn num_in_set() {
        let rs = single("status", "in", num_seq(&[200, 201, 204]));
        assert!(is_ignored(&rs, &make_entry(A))); // 200
        assert!(!is_ignored(&rs, &make_entry(B))); // 301
    }

    #[test]
    fn num_not_in_set() {
        let rs = single("status", "not_in", num_seq(&[200, 201, 204]));
        assert!(!is_ignored(&rs, &make_entry(A))); // 200 is in the set
        assert!(is_ignored(&rs, &make_entry(B))); // 301 is not
    }

    // ── response_time field ───────────────────────────────────────────────────

    #[test]
    fn response_time_gt_matches_present_field() {
        let rs = single("response_time", "gt", num(1000));
        assert!(is_ignored(&rs, &make_entry(RT))); // 2500ms > 1000
        assert!(!is_ignored(&rs, &make_entry(A))); // no rt field → no match
    }

    #[test]
    fn response_time_absent_never_matches() {
        // A has no us= field — all numeric ops on response_time must return false
        for op in &["eq", "neq", "gt", "lt", "gte", "lte"] {
            let rs = single("response_time", op, num(0));
            assert!(!is_ignored(&rs, &make_entry(A)), "op={op} should not match absent rt");
        }
        let rs = single("response_time", "between", num_seq(&[0, 9999999]));
        assert!(!is_ignored(&rs, &make_entry(A)));
        let rs = single("response_time", "in", num_seq(&[0]));
        assert!(!is_ignored(&rs, &make_entry(A)));
        let rs = single("response_time", "not_in", num_seq(&[0]));
        assert!(!is_ignored(&rs, &make_entry(A)));
    }

    #[test]
    fn response_time_between_inclusive() {
        let rs = single("response_time", "between", num_seq(&[2000, 3000]));
        assert!(is_ignored(&rs, &make_entry(RT))); // 2500 in [2000,3000]
        assert!(!is_ignored(&rs, &make_entry(A))); // absent
    }

    // ── Length ops ────────────────────────────────────────────────────────────

    // A url = "/static/foo.js" (14 chars), B url = "/old/page" (9 chars)

    #[test]
    fn len_gt() {
        let rs = single("url", "len_gt", num(10));
        assert!(is_ignored(&rs, &make_entry(A))); // 14 > 10
        assert!(!is_ignored(&rs, &make_entry(B))); // 9 not > 10
    }

    #[test]
    fn len_lt() {
        let rs = single("url", "len_lt", num(10));
        assert!(!is_ignored(&rs, &make_entry(A))); // 14 not < 10
        assert!(is_ignored(&rs, &make_entry(B))); // 9 < 10
    }

    #[test]
    fn len_gte_boundary() {
        let rs = single("url", "len_gte", num(9));
        assert!(is_ignored(&rs, &make_entry(A))); // 14 >= 9
        assert!(is_ignored(&rs, &make_entry(B))); // 9 == 9
    }

    #[test]
    fn len_lte_boundary() {
        let rs = single("url", "len_lte", num(9));
        assert!(!is_ignored(&rs, &make_entry(A))); // 14 > 9
        assert!(is_ignored(&rs, &make_entry(B))); // 9 == 9
    }

    #[test]
    fn len_eq() {
        let rs = single("url", "len_eq", num(9));
        assert!(!is_ignored(&rs, &make_entry(A))); // 14
        assert!(is_ignored(&rs, &make_entry(B))); // 9
    }

    #[test]
    fn len_between_inclusive() {
        let rs = single("url", "len_between", num_seq(&[9, 14]));
        assert!(is_ignored(&rs, &make_entry(A))); // 14
        assert!(is_ignored(&rs, &make_entry(B))); // 9
    }

    #[test]
    fn len_between_exclusive() {
        let rs = single("url", "len_between", num_seq(&[10, 13]));
        assert!(!is_ignored(&rs, &make_entry(A))); // 14 > 13
        assert!(!is_ignored(&rs, &make_entry(B))); // 9 < 10
    }

    #[test]
    fn len_op_on_numeric_field_is_error() {
        let err = RuleSet::compile(&[RawRule {
            name: "t".into(),
            enabled: true,
            when: RawWhen::List(vec![RawCondition {
                field: "status".into(),
                op: "len_gt".into(),
                value: num(5),
            }]),
            action: RawAction::Ignore,
        }]);
        assert!(err.is_err());
    }

    #[test]
    fn len_op_on_bucket_field_is_error() {
        let err = RuleSet::compile(&[RawRule {
            name: "t".into(),
            enabled: true,
            when: RawWhen::List(vec![RawCondition {
                field: "bucket".into(),
                op: "len_gt".into(),
                value: num(5),
            }]),
            action: RawAction::Ignore,
        }]);
        assert!(err.is_err());
    }

    // ── Match modes ───────────────────────────────────────────────────────────

    #[test]
    fn all_mode_requires_every_condition() {
        // status==301 AND url starts_with /old/ → only B matches
        let rs = RuleSet::compile(&[RawRule {
            name: "t".into(),
            enabled: true,
            when: RawWhen::All {
                all: vec![
                    RawCondition {
                        field: "status".into(),
                        op: "eq".into(),
                        value: num(301),
                    },
                    RawCondition {
                        field: "url".into(),
                        op: "starts_with".into(),
                        value: str_val("/old/"),
                    },
                ],
            },
            action: RawAction::Ignore,
        }])
        .unwrap();
        assert!(!is_ignored(&rs, &make_entry(A)));
        assert!(is_ignored(&rs, &make_entry(B)));
        assert!(!is_ignored(&rs, &make_entry(C)));
    }

    #[test]
    fn all_mode_short_circuits_on_first_false() {
        let rs = RuleSet::compile(&[RawRule {
            name: "t".into(),
            enabled: true,
            when: RawWhen::All {
                all: vec![
                    RawCondition {
                        field: "status".into(),
                        op: "eq".into(),
                        value: num(999),
                    },
                    RawCondition {
                        field: "url".into(),
                        op: "starts_with".into(),
                        value: str_val("/"),
                    },
                ],
            },
            action: RawAction::Ignore,
        }])
        .unwrap();
        assert!(!is_ignored(&rs, &make_entry(A)));
    }

    #[test]
    fn implicit_list_is_all() {
        let list_rs = RuleSet::compile(&[RawRule {
            name: "t".into(),
            enabled: true,
            when: RawWhen::List(vec![
                RawCondition {
                    field: "status".into(),
                    op: "eq".into(),
                    value: num(301),
                },
                RawCondition {
                    field: "url".into(),
                    op: "starts_with".into(),
                    value: str_val("/old/"),
                },
            ]),
            action: RawAction::Ignore,
        }])
        .unwrap();
        let all_rs = RuleSet::compile(&[RawRule {
            name: "t".into(),
            enabled: true,
            when: RawWhen::All {
                all: vec![
                    RawCondition {
                        field: "status".into(),
                        op: "eq".into(),
                        value: num(301),
                    },
                    RawCondition {
                        field: "url".into(),
                        op: "starts_with".into(),
                        value: str_val("/old/"),
                    },
                ],
            },
            action: RawAction::Ignore,
        }])
        .unwrap();
        for line in [A, B, C] {
            let e = make_entry(line);
            assert_eq!(is_ignored(&list_rs, &e), is_ignored(&all_rs, &e));
        }
    }

    #[test]
    fn any_mode_matches_on_first_true() {
        // status==404 OR ua contains Googlebot → B and C match
        let rs = RuleSet::compile(&[RawRule {
            name: "t".into(),
            enabled: true,
            when: RawWhen::Any {
                any: vec![
                    RawCondition {
                        field: "status".into(),
                        op: "eq".into(),
                        value: num(404),
                    },
                    RawCondition {
                        field: "user_agent".into(),
                        op: "contains".into(),
                        value: str_val("Googlebot"),
                    },
                ],
            },
            action: RawAction::Ignore,
        }])
        .unwrap();
        assert!(!is_ignored(&rs, &make_entry(A))); // 200, Mozilla
        assert!(is_ignored(&rs, &make_entry(B))); // Googlebot
        assert!(is_ignored(&rs, &make_entry(C))); // 404
    }

    #[test]
    fn any_mode_no_match() {
        let rs = RuleSet::compile(&[RawRule {
            name: "t".into(),
            enabled: true,
            when: RawWhen::Any {
                any: vec![
                    RawCondition {
                        field: "status".into(),
                        op: "eq".into(),
                        value: num(500),
                    },
                    RawCondition {
                        field: "user_agent".into(),
                        op: "eq".into(),
                        value: str_val("unknown"),
                    },
                ],
            },
            action: RawAction::Ignore,
        }])
        .unwrap();
        assert!(!is_ignored(&rs, &make_entry(A)));
        assert!(!is_ignored(&rs, &make_entry(B)));
        assert!(!is_ignored(&rs, &make_entry(C)));
    }

    // ── Fall-through rule matching ─────────────────────────────────────────────

    #[test]
    fn fall_through_both_hide_rules_accumulate_mask() {
        // Two hide rules both match A — masks should be ORed together.
        let rs = RuleSet::compile(&[
            RawRule {
                name: "hide-urls".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "status".into(),
                    op: "eq".into(),
                    value: num(200),
                }]),
                action: RawAction::Hide(vec!["top_urls".into()]),
            },
            RawRule {
                name: "hide-agents".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "url".into(),
                    op: "starts_with".into(),
                    value: str_val("/static/"),
                }]),
                action: RawAction::Hide(vec!["top_agents".into()]),
            },
        ])
        .unwrap();

        let mask = applied_hide(&rs, &make_entry(A)).expect("should match");
        assert!(mask.contains(HideMask::TOP_URLS));
        assert!(mask.contains(HideMask::TOP_AGENTS));
    }

    #[test]
    fn fall_through_ignore_short_circuits() {
        // Ignore fires on rule 1 — rule 2 (Hide) should never apply.
        let rs = RuleSet::compile(&[
            RawRule {
                name: "ignore-200".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "status".into(),
                    op: "eq".into(),
                    value: num(200),
                }]),
                action: RawAction::Ignore,
            },
            RawRule {
                name: "hide-static".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "url".into(),
                    op: "starts_with".into(),
                    value: str_val("/static/"),
                }]),
                action: RawAction::Hide(vec!["top_urls".into()]),
            },
        ])
        .unwrap();

        let matched = rs.apply(&make_entry(A)).expect("should match");
        assert!(matched.ignored);
        assert_eq!(matched.hide, HideMask::NONE, "hide should not accumulate after ignore");
    }

    #[test]
    fn fall_through_bucket_then_hide_by_bucket_condition() {
        // Rule 1 buckets /static/, Rule 2 hides if bucket == "static".
        let rs = RuleSet::compile(&[
            RawRule {
                name: "bucket-static".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "url".into(),
                    op: "starts_with".into(),
                    value: str_val("/static/"),
                }]),
                action: RawAction::Bucket("static".into()),
            },
            RawRule {
                name: "hide-bucketed-static".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "bucket".into(),
                    op: "eq".into(),
                    value: str_val("static"),
                }]),
                action: RawAction::Hide(vec!["top_urls".into()]),
            },
        ])
        .unwrap();

        let matched = rs.apply(&make_entry(A)).expect("should match A: /static/foo.js");
        assert_eq!(matched.bucket.map(|b| b.as_ref()), Some("static"));
        assert!(matched.hide.contains(HideMask::TOP_URLS));

        // B has /old/page — should not match either rule.
        assert!(rs.apply(&make_entry(B)).is_none());
    }

    #[test]
    fn fall_through_first_bucket_wins() {
        // Two bucket rules match A — first one assigns, second is skipped.
        let rs = RuleSet::compile(&[
            RawRule {
                name: "bucket-first".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "status".into(),
                    op: "eq".into(),
                    value: num(200),
                }]),
                action: RawAction::Bucket("first".into()),
            },
            RawRule {
                name: "bucket-second".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "url".into(),
                    op: "starts_with".into(),
                    value: str_val("/static/"),
                }]),
                action: RawAction::Bucket("second".into()),
            },
        ])
        .unwrap();

        let matched = rs.apply(&make_entry(A)).expect("should match");
        assert_eq!(matched.bucket.map(|b| b.as_ref()), Some("first"));
    }

    #[test]
    fn bucket_neq_prevents_double_bucketing() {
        // Use field: bucket, op: neq to guard against shadowing.
        let rs = RuleSet::compile(&[
            RawRule {
                name: "bucket-static".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "url".into(),
                    op: "starts_with".into(),
                    value: str_val("/static/"),
                }]),
                action: RawAction::Bucket("static".into()),
            },
            RawRule {
                name: "bucket-ok-responses".into(),
                enabled: true,
                when: RawWhen::All {
                    all: vec![
                        RawCondition {
                            field: "status".into(),
                            op: "eq".into(),
                            value: num(200),
                        },
                        RawCondition {
                            field: "bucket".into(),
                            op: "neq".into(),
                            value: str_val("static"),
                        },
                    ],
                },
                action: RawAction::Bucket("ok".into()),
            },
        ])
        .unwrap();

        // A: /static/foo.js, status 200 — gets "static", not "ok"
        let m = rs.apply(&make_entry(A)).expect("should match");
        assert_eq!(m.bucket.map(|b| b.as_ref()), Some("static"));

        // RT: /, status 200 — not /static/, gets "ok"
        let m = rs.apply(&make_entry(RT)).expect("should match");
        assert_eq!(m.bucket.map(|b| b.as_ref()), Some("ok"));
    }

    #[test]
    fn no_rules_never_matches() {
        let rs = RuleSet::compile(&[]).unwrap();
        assert!(rs.0.is_empty());
        assert!(rs.apply(&make_entry(A)).is_none());
    }

    #[test]
    fn no_match_across_multiple_rules() {
        let rs = RuleSet::compile(&[
            RawRule {
                name: "r1".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "status".into(),
                    op: "eq".into(),
                    value: num(404),
                }]),
                action: RawAction::Ignore,
            },
            RawRule {
                name: "r2".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "url".into(),
                    op: "starts_with".into(),
                    value: str_val("/api/"),
                }]),
                action: RawAction::Ignore,
            },
        ])
        .unwrap();
        assert!(rs.apply(&make_entry(A)).is_none());
    }

    // ── timing hide target ────────────────────────────────────────────────────

    #[test]
    fn timing_target_compiles_and_sets_bit() {
        let rs = RuleSet::compile(&[RawRule {
            name: "t".into(),
            enabled: true,
            when: RawWhen::List(vec![RawCondition {
                field: "url".into(),
                op: "starts_with".into(),
                value: str_val("/"),
            }]),
            action: RawAction::Hide(vec!["timing".into()]),
        }])
        .expect("compile");

        let mask = applied_hide(&rs, &make_entry(RT)).expect("expected Hide");
        assert!(mask.contains(HideMask::TIMING));
        assert!(!mask.contains(HideMask::TOP_URLS));
        assert!(!mask.contains(HideMask::TOP_HOSTS));
        assert!(!mask.contains(HideMask::TOP_REFS));
        assert!(!mask.contains(HideMask::TOP_AGENTS));
        assert!(!mask.contains(HideMask::TOP_COUNTRIES));
    }

    #[test]
    fn timing_combined_with_top_urls_sets_both_bits() {
        let rs = RuleSet::compile(&[RawRule {
            name: "t".into(),
            enabled: true,
            when: RawWhen::List(vec![RawCondition {
                field: "url".into(),
                op: "starts_with".into(),
                value: str_val("/"),
            }]),
            action: RawAction::Hide(vec!["timing".into(), "top_urls".into()]),
        }])
        .expect("compile");

        let mask = applied_hide(&rs, &make_entry(A)).expect("expected Hide");
        assert!(mask.contains(HideMask::TIMING));
        assert!(mask.contains(HideMask::TOP_URLS));
    }

    #[test]
    fn yaml_timing_target_deserialises() {
        let yaml = r#"
- name: "Exclude websockets from timing"
  when:
    - field: status
      op: eq
      value: 101
  action:
    hide: [timing]
"#;
        let raw: Vec<RawRule> = serde_yaml::from_str(yaml).expect("parse yaml");
        let rs = RuleSet::compile(&raw).expect("compile");
        assert!(rs.apply(&make_entry(A)).is_none()); // status 200, not 101
    }

    // ── Hide action ───────────────────────────────────────────────────────────

    #[test]
    fn hide_action_compiles_and_applies() {
        let rs = RuleSet::compile(&[RawRule {
            name: "t".into(),
            enabled: true,
            when: RawWhen::List(vec![RawCondition {
                field: "url".into(),
                op: "starts_with".into(),
                value: str_val("/static/"),
            }]),
            action: RawAction::Hide(vec!["top_urls".into(), "top_refs".into()]),
        }])
        .expect("compile");

        let entry_a = make_entry(A); // url = /static/foo.js → should match
        let entry_b = make_entry(B); // url = /old/page     → should not match

        assert!(applied_hide(&rs, &entry_a).is_some());
        assert!(rs.apply(&entry_b).is_none());
    }

    #[test]
    fn hide_mask_contains_only_named_tables() {
        let rs = RuleSet::compile(&[RawRule {
            name: "t".into(),
            enabled: true,
            when: RawWhen::List(vec![RawCondition {
                field: "url".into(),
                op: "starts_with".into(),
                value: str_val("/static/"),
            }]),
            action: RawAction::Hide(vec!["top_urls".into(), "top_refs".into()]),
        }])
        .expect("compile");

        let mask = applied_hide(&rs, &make_entry(A)).expect("expected Hide");
        assert!(mask.contains(HideMask::TOP_URLS));
        assert!(mask.contains(HideMask::TOP_REFS));
        assert!(!mask.contains(HideMask::TOP_HOSTS));
        assert!(!mask.contains(HideMask::TOP_AGENTS));
        assert!(!mask.contains(HideMask::TOP_COUNTRIES));
        assert!(!mask.contains(HideMask::TIMING));
    }

    #[test]
    fn hide_unknown_table_is_error() {
        let err = RuleSet::compile(&[RawRule {
            name: "t".into(),
            enabled: true,
            when: RawWhen::List(vec![RawCondition {
                field: "url".into(),
                op: "starts_with".into(),
                value: str_val("/static/"),
            }]),
            action: RawAction::Hide(vec!["no_such_target".into()]),
        }]);
        assert!(err.is_err());
    }

    #[test]
    fn hide_and_ignore_in_same_ruleset_ignore_wins() {
        // With fall-through: Hide accumulates, then Ignore fires and drops the entry.
        let rs = RuleSet::compile(&[
            RawRule {
                name: "hide-static".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "url".into(),
                    op: "starts_with".into(),
                    value: str_val("/static/"),
                }]),
                action: RawAction::Hide(vec!["top_urls".into()]),
            },
            RawRule {
                name: "ignore-200".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "status".into(),
                    op: "eq".into(),
                    value: num(200),
                }]),
                action: RawAction::Ignore,
            },
        ])
        .expect("compile");

        let matched = rs.apply(&make_entry(A)).expect("should match");
        assert!(matched.ignored, "entry should be dropped");
    }

    // ── Compilation errors ────────────────────────────────────────────────────

    #[test]
    fn unknown_field_is_error() {
        let result = RuleSet::compile(&[RawRule {
            name: "t".into(),
            enabled: true,
            when: RawWhen::List(vec![RawCondition {
                field: "no_such_field".into(),
                op: "eq".into(),
                value: str_val("x"),
            }]),
            action: RawAction::Ignore,
        }]);
        let msg = result.err().expect("should have failed").to_string();
        assert!(msg.contains("no_such_field"), "error was: {msg}");
    }

    #[test]
    fn unknown_op_is_error() {
        let result = RuleSet::compile(&[RawRule {
            name: "t".into(),
            enabled: true,
            when: RawWhen::List(vec![RawCondition {
                field: "url".into(),
                op: "fuzzy_match".into(),
                value: str_val("x"),
            }]),
            action: RawAction::Ignore,
        }]);
        let msg = result.err().expect("should have failed").to_string();
        assert!(msg.contains("fuzzy_match"), "error was: {msg}");
    }

    #[test]
    fn invalid_regex_is_error() {
        let err = RuleSet::compile(&[RawRule {
            name: "t".into(),
            enabled: true,
            when: RawWhen::List(vec![RawCondition {
                field: "url".into(),
                op: "matches".into(),
                value: str_val("[unclosed"),
            }]),
            action: RawAction::Ignore,
        }]);
        assert!(err.is_err());
    }

    #[test]
    fn between_wrong_arity_is_error() {
        let err = RuleSet::compile(&[RawRule {
            name: "t".into(),
            enabled: true,
            when: RawWhen::List(vec![RawCondition {
                field: "status".into(),
                op: "between".into(),
                value: num_seq(&[200]),
            }]),
            action: RawAction::Ignore,
        }]);
        assert!(err.is_err());
    }

    #[test]
    fn in_with_scalar_is_error() {
        let err = RuleSet::compile(&[RawRule {
            name: "t".into(),
            enabled: true,
            when: RawWhen::List(vec![RawCondition {
                field: "url".into(),
                op: "in".into(),
                value: str_val("/foo"),
            }]),
            action: RawAction::Ignore,
        }]);
        assert!(err.is_err());
    }

    // ── Sample action ─────────────────────────────────────────────────────────

    fn make_sample_rs(rate: f64) -> RuleSet {
        RuleSet::compile(&[RawRule {
            name: "t".into(),
            enabled: true,
            when: RawWhen::List(vec![RawCondition {
                field: "status".into(),
                op: "eq".into(),
                value: num(200),
            }]),
            action: RawAction::Sample(rate),
        }])
        .expect("compile")
    }

    #[test]
    fn sample_rate_zero_always_drops() {
        // rate=0.0 means drop all matching entries
        let rs = make_sample_rs(0.0);
        let entry = make_entry(A); // status 200
        let m = rs.apply(&entry).expect("should match");
        assert!(m.sampled, "rate=0.0 should always drop");
    }

    #[test]
    fn sample_rate_one_always_keeps() {
        // rate=1.0 means keep all matching entries
        let rs = make_sample_rs(1.0);
        let entry = make_entry(A); // status 200
        let m = rs.apply(&entry).expect("should match");
        assert!(!m.sampled, "rate=1.0 should never drop");
    }

    #[test]
    fn sample_rate_zero_compiles() {
        let rs = make_sample_rs(0.0);
        assert!(rs.apply(&make_entry(A)).is_some());
    }

    #[test]
    fn sample_rate_one_compiles() {
        let rs = make_sample_rs(1.0);
        assert!(rs.apply(&make_entry(A)).is_some());
    }

    #[test]
    fn sample_rate_above_one_is_error() {
        let err = RuleSet::compile(&[RawRule {
            name: "t".into(),
            enabled: true,
            when: RawWhen::List(vec![RawCondition {
                field: "status".into(),
                op: "eq".into(),
                value: num(200),
            }]),
            action: RawAction::Sample(1.1),
        }]);
        assert!(err.is_err());
    }

    #[test]
    fn sample_rate_negative_is_error() {
        let err = RuleSet::compile(&[RawRule {
            name: "t".into(),
            enabled: true,
            when: RawWhen::List(vec![RawCondition {
                field: "status".into(),
                op: "eq".into(),
                value: num(200),
            }]),
            action: RawAction::Sample(-0.1),
        }]);
        assert!(err.is_err());
    }

    #[test]
    fn sample_non_matching_entry_returns_none() {
        let rs = make_sample_rs(0.5);
        // Entry B has status 301, not 200 — rule does not match
        assert!(rs.apply(&make_entry(B)).is_none());
    }

    #[test]
    fn yaml_sample_action_deserialises() {
        let yaml = r#"
- name: "Sample traffic"
  when:
    - field: status
      op: eq
      value: 200
  action:
    sample: 0.0
"#;
        // rate=0.0 so always drops — deterministic for testing
        let raw: Vec<RawRule> = serde_yaml::from_str(yaml).expect("parse yaml");
        let rs = RuleSet::compile(&raw).expect("compile");
        let m = rs.apply(&make_entry(A)).expect("should match");
        assert!(m.sampled);
        assert!(rs.apply(&make_entry(B)).is_none()); // status 301
    }

    // ── YAML round-trip (config parsing) ─────────────────────────────────────

    #[test]
    fn yaml_roundtrip_any_mode() {
        let yaml = r#"
- name: "Bot filter"
  when:
    any:
      - field: user_agent
        op: contains
        value: "Googlebot"
      - field: user_agent
        op: contains
        value: "bingbot"
  action: ignore
"#;
        let raw: Vec<RawRule> = serde_yaml::from_str(yaml).expect("parse yaml");
        let rs = RuleSet::compile(&raw).expect("compile");
        assert!(is_ignored(&rs, &make_entry(B))); // Googlebot
        assert!(!is_ignored(&rs, &make_entry(A)));
    }

    #[test]
    fn yaml_roundtrip_implicit_all() {
        let yaml = r#"
- name: "Redirect from /old/"
  when:
    - field: status
      op: eq
      value: 301
    - field: url
      op: starts_with
      value: "/old/"
  action: ignore
"#;
        let raw: Vec<RawRule> = serde_yaml::from_str(yaml).expect("parse yaml");
        let rs = RuleSet::compile(&raw).expect("compile");
        assert!(is_ignored(&rs, &make_entry(B))); // 301 + /old/
        assert!(!is_ignored(&rs, &make_entry(A))); // 200
        assert!(!is_ignored(&rs, &make_entry(C))); // 404
    }

    #[test]
    fn yaml_roundtrip_in_list() {
        let yaml = r#"
- name: "Redirect statuses"
  when:
    - field: status
      op: in
      value: [301, 302, 303]
  action: ignore
"#;
        let raw: Vec<RawRule> = serde_yaml::from_str(yaml).expect("parse yaml");
        let rs = RuleSet::compile(&raw).expect("compile");
        assert!(!is_ignored(&rs, &make_entry(A))); // 200
        assert!(is_ignored(&rs, &make_entry(B))); // 301
        assert!(!is_ignored(&rs, &make_entry(C))); // 404
    }

    #[test]
    fn yaml_hide_action_deserialises_from_map() {
        let yaml = r#"
- name: "Self-referrals"
  when:
    - field: referer
      op: contains
      value: "example"
  action:
    hide: [top_refs]
"#;
        let raw: Vec<RawRule> = serde_yaml::from_str(yaml).expect("parse yaml");
        let rs = RuleSet::compile(&raw).expect("compile");
        let mask = applied_hide(&rs, &make_entry(A)).expect("expected hide");
        assert!(mask.contains(HideMask::TOP_REFS));
        assert!(rs.apply(&make_entry(B)).is_none()); // referer is "-"
    }

    #[test]
    fn yaml_ignore_action_still_deserialises() {
        let yaml = r#"
- name: "Drop bots"
  when:
    - field: user_agent
      op: contains
      value: "Googlebot"
  action: ignore
"#;
        let raw: Vec<RawRule> = serde_yaml::from_str(yaml).expect("parse yaml");
        let rs = RuleSet::compile(&raw).expect("compile");
        let m = rs.apply(&make_entry(B)).expect("should match");
        assert!(m.ignored);
    }

    // ── Bucket action ─────────────────────────────────────────────────────────

    #[test]
    fn yaml_bucket_action_deserialises() {
        let yaml = r#"
- name: "Bucket API traffic"
  when:
    - field: url
      op: starts_with
      value: "/api/"
  action:
    bucket: api
"#;
        let raw: Vec<RawRule> = serde_yaml::from_str(yaml).expect("parse yaml");
        let rs = RuleSet::compile(&raw).expect("compile");
        // None of A/B/C have /api/ prefix — no match.
        assert!(rs.apply(&make_entry(A)).is_none());
    }

    #[test]
    fn bucket_assigned_correctly() {
        let rs = RuleSet::compile(&[RawRule {
            name: "bucket-static".into(),
            enabled: true,
            when: RawWhen::List(vec![RawCondition {
                field: "url".into(),
                op: "starts_with".into(),
                value: str_val("/static/"),
            }]),
            action: RawAction::Bucket("static-assets".into()),
        }])
        .expect("compile");

        assert_eq!(
            applied_bucket(&rs, &make_entry(A)),
            Some("static-assets".to_string())
        );
        assert_eq!(applied_bucket(&rs, &make_entry(B)), None);
    }

    #[test]
    fn bucket_empty_name_is_error() {
        let err = RuleSet::compile(&[RawRule {
            name: "t".into(),
            enabled: true,
            when: RawWhen::List(vec![RawCondition {
                field: "url".into(),
                op: "starts_with".into(),
                value: str_val("/"),
            }]),
            action: RawAction::Bucket("".into()),
        }]);
        assert!(err.is_err());
    }

    #[test]
    fn bucket_slash_in_name_is_error() {
        let err = RuleSet::compile(&[RawRule {
            name: "t".into(),
            enabled: true,
            when: RawWhen::List(vec![RawCondition {
                field: "url".into(),
                op: "starts_with".into(),
                value: str_val("/"),
            }]),
            action: RawAction::Bucket("foo/bar".into()),
        }]);
        assert!(err.is_err());
    }

    #[test]
    fn bucket_slug_collision_is_error() {
        let err = RuleSet::compile(&[
            RawRule {
                name: "r1".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "url".into(),
                    op: "starts_with".into(),
                    value: str_val("/a/"),
                }]),
                action: RawAction::Bucket("API Traffic".into()),
            },
            RawRule {
                name: "r2".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "url".into(),
                    op: "starts_with".into(),
                    value: str_val("/b/"),
                }]),
                action: RawAction::Bucket("api-traffic".into()),
            },
        ]);
        assert!(err.is_err(), "slug collision should be rejected");
    }

    // ── enabled flag ─────────────────────────────────────────────────────────

    #[test]
    fn disabled_rule_is_skipped() {
        let yaml = r#"
- name: "disabled"
  enabled: false
  when:
    - field: status
      op: eq
      value: 200
  action: ignore
"#;
        let raw: Vec<RawRule> = serde_yaml::from_str(yaml).expect("parse yaml");
        assert!(!raw[0].enabled);
        let rs = RuleSet::compile(&raw).expect("compile");
        assert!(rs.apply(&make_entry(A)).is_none());
    }

    #[test]
    fn enabled_true_explicit_works() {
        let yaml = r#"
- name: "enabled-explicit"
  enabled: true
  when:
    - field: status
      op: eq
      value: 200
  action: ignore
"#;
        let raw: Vec<RawRule> = serde_yaml::from_str(yaml).expect("parse yaml");
        let rs = RuleSet::compile(&raw).expect("compile");
        assert!(is_ignored(&rs, &make_entry(A)));
    }

    #[test]
    fn enabled_defaults_to_true_when_omitted() {
        let yaml = r#"
- name: "no-enabled-field"
  when:
    - field: status
      op: eq
      value: 200
  action: ignore
"#;
        let raw: Vec<RawRule> = serde_yaml::from_str(yaml).expect("parse yaml");
        assert!(raw[0].enabled);
        let rs = RuleSet::compile(&raw).expect("compile");
        assert!(is_ignored(&rs, &make_entry(A)));
    }

    // ── make_slug ─────────────────────────────────────────────────────────────

    #[test]
    fn slug_basic() {
        assert_eq!(make_slug("api"), "api");
        assert_eq!(make_slug("API Traffic"), "api-traffic");
        assert_eq!(make_slug("api-traffic"), "api-traffic");
        assert_eq!(make_slug("  leading spaces  "), "leading-spaces");
        assert_eq!(make_slug("foo__bar"), "foo-bar");
    }

    #[test]
    fn slug_uppercase_lowercased() {
        assert_eq!(make_slug("MyBucket"), "mybucket");
        assert_eq!(make_slug("UPPER"), "upper");
    }

    #[test]
    fn slug_collapses_repeated_separators() {
        assert_eq!(make_slug("a--b"), "a-b");
        assert_eq!(make_slug("a___b"), "a-b");
        assert_eq!(make_slug("a - b"), "a-b");
    }

    #[test]
    fn slug_strips_leading_trailing_separators() {
        assert_eq!(make_slug("--api--"), "api");
        assert_eq!(make_slug("  api  "), "api");
    }

    #[test]
    fn slug_preserves_numbers() {
        assert_eq!(make_slug("bucket123"), "bucket123");
        assert_eq!(make_slug("404-errors"), "404-errors");
    }

    #[test]
    fn slug_all_special_chars_is_empty() {
        assert_eq!(make_slug("!!!"), "");
        assert_eq!(make_slug("---"), "");
    }

    #[test]
    fn slug_non_ascii_chars_treated_as_separator() {
        // Non-ASCII chars (é, ü, etc.) are not ASCII alphanumeric → become '-'.
        assert_eq!(make_slug("café"), "caf");
        assert_eq!(make_slug("über"), "ber");
        assert_eq!(make_slug("naïve"), "na-ve");
    }

    #[test]
    fn bucket_backslash_in_name_is_error() {
        let err = RuleSet::compile(&[RawRule {
            name: "t".into(),
            enabled: true,
            when: RawWhen::List(vec![RawCondition {
                field: "url".into(),
                op: "starts_with".into(),
                value: str_val("/"),
            }]),
            action: RawAction::Bucket("foo\\bar".into()),
        }]);
        assert!(err.is_err());
    }

    #[test]
    fn bucket_all_special_chars_empty_slug_is_error() {
        let err = RuleSet::compile(&[RawRule {
            name: "t".into(),
            enabled: true,
            when: RawWhen::List(vec![RawCondition {
                field: "url".into(),
                op: "starts_with".into(),
                value: str_val("/"),
            }]),
            action: RawAction::Bucket("!!!".into()),
        }]);
        let msg = err.err().expect("should fail").to_string();
        assert!(msg.contains("empty slug"), "error was: {msg}");
    }

    #[test]
    fn yaml_bucket_action_matching_entry() {
        // Verify the bucket is actually assigned when the entry matches.
        let yaml = r#"
- name: "Bucket static assets"
  when:
    - field: url
      op: starts_with
      value: "/static/"
  action:
    bucket: static
"#;
        let raw: Vec<RawRule> = serde_yaml::from_str(yaml).expect("parse yaml");
        let rs = RuleSet::compile(&raw).expect("compile");
        // A: /static/foo.js → should be bucketed as "static".
        let m = rs.apply(&make_entry(A)).expect("should match");
        assert_eq!(m.bucket.map(|b| b.as_ref()), Some("static"));
        assert!(!m.ignored);
        // B: /old/page → no match.
        assert!(rs.apply(&make_entry(B)).is_none());
    }

    // ── MatchEffect types ──────────────────────────────────────────────────────

    #[test]
    fn match_effect_bucketed_type_in_effects() {
        let rs = RuleSet::compile(&[RawRule {
            name: "bucket-static".into(),
            enabled: true,
            when: RawWhen::List(vec![RawCondition {
                field: "url".into(),
                op: "starts_with".into(),
                value: str_val("/static/"),
            }]),
            action: RawAction::Bucket("static".into()),
        }])
        .unwrap();

        let m = rs.apply(&make_entry(A)).expect("should match");
        assert_eq!(m.effects.len(), 1);
        assert!(matches!(m.effects[0].1, MatchEffect::Bucketed));
    }

    #[test]
    fn match_effect_hidden_type_in_effects() {
        let rs = RuleSet::compile(&[RawRule {
            name: "hide-static".into(),
            enabled: true,
            when: RawWhen::List(vec![RawCondition {
                field: "url".into(),
                op: "starts_with".into(),
                value: str_val("/static/"),
            }]),
            action: RawAction::Hide(vec!["top_urls".into()]),
        }])
        .unwrap();

        let m = rs.apply(&make_entry(A)).expect("should match");
        assert_eq!(m.effects.len(), 1);
        assert!(matches!(m.effects[0].1, MatchEffect::Hidden));
    }

    #[test]
    fn match_effect_ignored_type_in_effects() {
        let rs = RuleSet::compile(&[RawRule {
            name: "ignore-200".into(),
            enabled: true,
            when: RawWhen::List(vec![RawCondition {
                field: "status".into(),
                op: "eq".into(),
                value: num(200),
            }]),
            action: RawAction::Ignore,
        }])
        .unwrap();

        let m = rs.apply(&make_entry(A)).expect("should match");
        assert_eq!(m.effects.len(), 1);
        assert!(matches!(m.effects[0].1, MatchEffect::Ignored));
    }

    #[test]
    fn shadowed_bucket_rule_does_not_appear_in_effects() {
        // Rule 1 buckets as "first". Rule 2 also tries to bucket — it matches but
        // the bucket is shadowed, so rule 2 must NOT appear in the effects list.
        let rs = RuleSet::compile(&[
            RawRule {
                name: "bucket-first".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "status".into(),
                    op: "eq".into(),
                    value: num(200),
                }]),
                action: RawAction::Bucket("first".into()),
            },
            RawRule {
                name: "bucket-second".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "url".into(),
                    op: "starts_with".into(),
                    value: str_val("/static/"),
                }]),
                action: RawAction::Bucket("second".into()),
            },
        ])
        .unwrap();

        // A matches both rules (status 200 and /static/ prefix).
        let m = rs.apply(&make_entry(A)).expect("should match");
        assert_eq!(m.bucket.map(|b| b.as_ref()), Some("first"), "first bucket wins");
        let effect_names: Vec<&str> = m.effects.iter().map(|(n, _)| n.as_ref()).collect();
        assert!(effect_names.contains(&"bucket-first"), "rule 1 must be in effects");
        assert!(!effect_names.contains(&"bucket-second"), "shadowed rule 2 must not be in effects");
    }

    // ── Fall-through: Sample + Bucket interaction ──────────────────────────────

    #[test]
    fn sample_keep_then_bucket_fires() {
        // Sample at 1.0 always keeps. A bucket rule after it must still assign.
        let rs = RuleSet::compile(&[
            RawRule {
                name: "sample-keep".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "status".into(),
                    op: "eq".into(),
                    value: num(200),
                }]),
                action: RawAction::Sample(1.0),
            },
            RawRule {
                name: "bucket-static".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "url".into(),
                    op: "starts_with".into(),
                    value: str_val("/static/"),
                }]),
                action: RawAction::Bucket("static".into()),
            },
        ])
        .unwrap();

        let m = rs.apply(&make_entry(A)).expect("should match");
        assert!(!m.sampled, "rate=1.0 keeps");
        assert_eq!(m.bucket.map(|b| b.as_ref()), Some("static"), "bucket must fire after kept sample");
    }

    #[test]
    fn sample_drop_then_bucket_does_not_fire() {
        // Sample at 0.0 always drops. Short-circuits before bucket can assign.
        let rs = RuleSet::compile(&[
            RawRule {
                name: "sample-drop".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "status".into(),
                    op: "eq".into(),
                    value: num(200),
                }]),
                action: RawAction::Sample(0.0),
            },
            RawRule {
                name: "bucket-static".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "url".into(),
                    op: "starts_with".into(),
                    value: str_val("/static/"),
                }]),
                action: RawAction::Bucket("static".into()),
            },
        ])
        .unwrap();

        let m = rs.apply(&make_entry(A)).expect("sample matched");
        assert!(m.sampled, "should be dropped");
        assert!(m.bucket.is_none(), "bucket must not be assigned after sample drop");
    }

    // ── Fall-through: Bucket + Ignore interaction ─────────────────────────────

    #[test]
    fn bucket_assigned_then_ignore_fires_both_take_effect() {
        // Rule 1 assigns bucket. Rule 2 ignores. Both should take effect: bucket is Some
        // and ignored is true.
        let rs = RuleSet::compile(&[
            RawRule {
                name: "bucket-static".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "url".into(),
                    op: "starts_with".into(),
                    value: str_val("/static/"),
                }]),
                action: RawAction::Bucket("static".into()),
            },
            RawRule {
                name: "ignore-200".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "status".into(),
                    op: "eq".into(),
                    value: num(200),
                }]),
                action: RawAction::Ignore,
            },
        ])
        .unwrap();

        // A: /static/foo.js, status 200 — both rules match.
        let m = rs.apply(&make_entry(A)).expect("should match");
        assert_eq!(m.bucket.map(|b| b.as_ref()), Some("static"), "bucket must be assigned");
        assert!(m.ignored, "entry must be ignored");

        // Effects: bucket-static (Bucketed) then ignore-200 (Ignored).
        assert_eq!(m.effects.len(), 2);
        assert!(matches!(m.effects[0].1, MatchEffect::Bucketed));
        assert!(matches!(m.effects[1].1, MatchEffect::Ignored));
    }

    #[test]
    fn ignore_before_bucket_short_circuits_bucket_assignment() {
        // Rule 1 ignores. Rule 2 would bucket. Since Ignore short-circuits, bucket
        // must not be assigned.
        let rs = RuleSet::compile(&[
            RawRule {
                name: "ignore-200".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "status".into(),
                    op: "eq".into(),
                    value: num(200),
                }]),
                action: RawAction::Ignore,
            },
            RawRule {
                name: "bucket-static".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "url".into(),
                    op: "starts_with".into(),
                    value: str_val("/static/"),
                }]),
                action: RawAction::Bucket("static".into()),
            },
        ])
        .unwrap();

        let m = rs.apply(&make_entry(A)).expect("should match");
        assert!(m.ignored);
        assert!(m.bucket.is_none(), "bucket must not be assigned after Ignore short-circuits");
    }

    // ── Bucket field conditions ────────────────────────────────────────────────

    #[test]
    fn bucket_field_in_op_matches_assigned_bucket() {
        // Rule 1 assigns "static". Rule 2 checks bucket in ["static", "api"].
        let rs = RuleSet::compile(&[
            RawRule {
                name: "assign".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "url".into(),
                    op: "starts_with".into(),
                    value: str_val("/static/"),
                }]),
                action: RawAction::Bucket("static".into()),
            },
            RawRule {
                name: "check-in".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "bucket".into(),
                    op: "in".into(),
                    value: seq(&["static", "api"]),
                }]),
                action: RawAction::Ignore,
            },
        ])
        .unwrap();

        // A: /static/foo.js — gets bucket "static", which is in ["static", "api"] → ignored.
        let m = rs.apply(&make_entry(A)).expect("should match");
        assert_eq!(m.bucket.map(|b| b.as_ref()), Some("static"));
        assert!(m.ignored);

        // B: /old/page — no bucket → "" in ["static", "api"] → false → not ignored.
        assert!(rs.apply(&make_entry(B)).is_none());
    }

    #[test]
    fn bucket_field_not_in_op_excludes_assigned_bucket() {
        // Rule 1 assigns "static". Rule 2 hides if bucket not_in ["api"].
        let rs = RuleSet::compile(&[
            RawRule {
                name: "assign".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "url".into(),
                    op: "starts_with".into(),
                    value: str_val("/static/"),
                }]),
                action: RawAction::Bucket("static".into()),
            },
            RawRule {
                name: "check-not-in".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "bucket".into(),
                    op: "not_in".into(),
                    value: seq(&["api"]),
                }]),
                action: RawAction::Hide(vec!["top_urls".into()]),
            },
        ])
        .unwrap();

        // A: bucket "static", not_in ["api"] → true → hide mask set.
        let m = rs.apply(&make_entry(A)).expect("should match");
        assert!(m.hide.contains(HideMask::TOP_URLS));

        // B: no bucket (""), not_in ["api"] → "" not in ["api"] → true → hide mask set.
        let m = rs.apply(&make_entry(B)).expect("B: rule 2 matches (empty not in [api])");
        assert!(m.hide.contains(HideMask::TOP_URLS));
    }

    #[test]
    fn bucket_field_eq_with_no_bucket_does_not_match_nonempty_value() {
        // Rule checks bucket == "static" — without rule 1 assigning a bucket,
        // field_str returns "" which never equals "static".
        let rs = RuleSet::compile(&[RawRule {
            name: "check-bucket".into(),
            enabled: true,
            when: RawWhen::List(vec![RawCondition {
                field: "bucket".into(),
                op: "eq".into(),
                value: str_val("static"),
            }]),
            action: RawAction::Ignore,
        }])
        .unwrap();

        // No bucket assigned to any entry — rule should never match.
        assert!(rs.apply(&make_entry(A)).is_none());
        assert!(rs.apply(&make_entry(B)).is_none());
        assert!(rs.apply(&make_entry(C)).is_none());
    }

    #[test]
    fn bucket_field_eq_empty_string_matches_unbucketed_entry() {
        // Checking field: bucket, op: eq, value: "" — tests that the empty-string
        // sentinel for "no bucket" is accessible via condition matching.
        let rs = RuleSet::compile(&[RawRule {
            name: "check-empty-bucket".into(),
            enabled: true,
            when: RawWhen::List(vec![RawCondition {
                field: "bucket".into(),
                op: "eq".into(),
                value: str_val(""),
            }]),
            action: RawAction::Ignore,
        }])
        .unwrap();

        // Entries have no bucket → "" == "" → matches.
        assert!(is_ignored(&rs, &make_entry(A)));
    }

    // ── Effects list ──────────────────────────────────────────────────────────

    #[test]
    fn effects_list_records_all_matched_rules() {
        // Three rules all match A: hide, hide, bucket. Effects should list all three.
        let rs = RuleSet::compile(&[
            RawRule {
                name: "r1-hide".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "status".into(),
                    op: "eq".into(),
                    value: num(200),
                }]),
                action: RawAction::Hide(vec!["top_urls".into()]),
            },
            RawRule {
                name: "r2-hide".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "url".into(),
                    op: "starts_with".into(),
                    value: str_val("/static/"),
                }]),
                action: RawAction::Hide(vec!["top_agents".into()]),
            },
            RawRule {
                name: "r3-bucket".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "url".into(),
                    op: "starts_with".into(),
                    value: str_val("/static/"),
                }]),
                action: RawAction::Bucket("static".into()),
            },
        ])
        .unwrap();

        let m = rs.apply(&make_entry(A)).expect("should match");
        let rule_names: Vec<&str> = m.effects.iter().map(|(n, _)| n.as_ref()).collect();
        assert!(rule_names.contains(&"r1-hide"), "r1 should appear in effects");
        assert!(rule_names.contains(&"r2-hide"), "r2 should appear in effects");
        assert!(rule_names.contains(&"r3-bucket"), "r3 should appear in effects");
        assert_eq!(m.effects.len(), 3);
    }

    #[test]
    fn effects_list_stops_at_ignore() {
        // Ignore fires on rule 2 — rule 3 (hide) should never run, so effects has 2 entries.
        let rs = RuleSet::compile(&[
            RawRule {
                name: "r1-hide".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "url".into(),
                    op: "starts_with".into(),
                    value: str_val("/static/"),
                }]),
                action: RawAction::Hide(vec!["top_urls".into()]),
            },
            RawRule {
                name: "r2-ignore".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "status".into(),
                    op: "eq".into(),
                    value: num(200),
                }]),
                action: RawAction::Ignore,
            },
            RawRule {
                name: "r3-hide".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "url".into(),
                    op: "starts_with".into(),
                    value: str_val("/"),
                }]),
                action: RawAction::Hide(vec!["top_agents".into()]),
            },
        ])
        .unwrap();

        let m = rs.apply(&make_entry(A)).expect("should match");
        assert!(m.ignored);
        assert_eq!(m.effects.len(), 2, "only r1 and r2 effects, not r3");
    }

    // ── Sample short-circuits ─────────────────────────────────────────────────

    #[test]
    fn sample_at_zero_short_circuits_subsequent_rules() {
        // sample rate=0.0 always drops. A hide rule after it must not run.
        let rs = RuleSet::compile(&[
            RawRule {
                name: "sample-drop".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "status".into(),
                    op: "eq".into(),
                    value: num(200),
                }]),
                action: RawAction::Sample(0.0),
            },
            RawRule {
                name: "hide-after".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "url".into(),
                    op: "starts_with".into(),
                    value: str_val("/static/"),
                }]),
                action: RawAction::Hide(vec!["top_urls".into()]),
            },
        ])
        .unwrap();

        let m = rs.apply(&make_entry(A)).expect("sample matched");
        assert!(m.sampled, "should be dropped by sample");
        assert_eq!(m.hide, HideMask::NONE, "hide rule must not have run after sample drop");
    }

    #[test]
    fn sample_at_one_continues_evaluating_subsequent_rules() {
        // sample rate=1.0 always keeps. A hide rule after it must still run.
        let rs = RuleSet::compile(&[
            RawRule {
                name: "sample-keep".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "status".into(),
                    op: "eq".into(),
                    value: num(200),
                }]),
                action: RawAction::Sample(1.0),
            },
            RawRule {
                name: "hide-after".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "url".into(),
                    op: "starts_with".into(),
                    value: str_val("/static/"),
                }]),
                action: RawAction::Hide(vec!["top_urls".into()]),
            },
        ])
        .unwrap();

        let m = rs.apply(&make_entry(A)).expect("should match");
        assert!(!m.sampled, "rate=1.0 keeps");
        assert!(m.hide.contains(HideMask::TOP_URLS), "hide rule must run after kept sample");
    }
}
