# Rule-based filtering and bucketing

Rules let you filter, hide, sample, and classify log entries before they reach the aggregator. They are evaluated in the parser thread — the same place bot filtering happens — so a matched entry costs nothing beyond the initial parse.

Rules are compiled once at startup. The hot path does no allocation, no string comparisons on operator names, and no regex compilation.

## Config format

Add a `rules:` list to your config file. Each rule has a `name`, a `when:` block, and an `action:`. Rules also accept an optional `enabled` boolean (default: `true`) — set it to `false` to disable a rule without removing it.

```yaml
rules:
  - name: "Ignore asset requests"
    when:
      - field: url
        op: starts_with
        value: "/static/"
    action: ignore

  - name: "Bucket API traffic"
    when:
      - field: url
        op: starts_with
        value: "/api/"
    action:
      bucket: api

  - name: "Sample health-check noise"
    when:
      - field: url
        op: eq
        value: "/healthz"
    action:
      sample: 0.05

  - name: "Temporarily disabled rule"
    enabled: false
    when:
      - field: url
        op: starts_with
        value: "/debug/"
    action: ignore
```

---

## Fall-through rule evaluation

Rules are evaluated in order and **all matching rules apply** — evaluation does not stop at the first match.

Each rule's action accumulates independently:

- `ignore` — drops the entry immediately and stops evaluation. No further rules fire.
- `hide` masks — OR together across all matching rules.
- `bucket` — the first matching `bucket` action assigns the bucket; later `bucket` rules are skipped (with a one-time warning — see below).
- `sample` — the first matching `sample` rule applies; if it drops the entry, evaluation stops.

This means you can separate concerns cleanly:

```yaml
rules:
  # Rule 1: assign a bucket to API traffic
  - name: "Bucket API traffic"
    when:
      - field: url
        op: starts_with
        value: "/api/"
    action:
      bucket: api

  # Rule 2: hide API from global URL tables — conditions don't need repeating
  - name: "Hide API from top URLs"
    when:
      - field: bucket
        op: eq
        value: api
    action:
      hide: [top_urls]
```

---

## `when:` — match modes

### Implicit `all` (bare list)

A bare list of conditions is equivalent to `all`. All conditions must match.

```yaml
when:
  - field: status
    op: eq
    value: 404
  - field: url
    op: starts_with
    value: "/wp-"
```

### `all:`

Explicit version of the above. All conditions must match (logical AND). Short-circuits on the first failure.

```yaml
when:
  all:
    - field: status
      op: eq
      value: 301
    - field: url
      op: starts_with
      value: "/old/"
```

### `any:`

At least one condition must match (logical OR). Short-circuits on the first success.

```yaml
when:
  any:
    - field: user_agent
      op: contains
      value: "Googlebot"
    - field: user_agent
      op: contains
      value: "bingbot"
```

---

## Fields

| Field           | Type             | Description                                |
|-----------------|------------------|--------------------------------------------|
| `ip`            | string           | Client IP address                          |
| `method`        | string           | HTTP method (`GET`, `POST`, …)             |
| `url`           | string           | Request path (no query string)             |
| `referer`       | string           | `Referer` header value                     |
| `user_agent`    | string           | `User-Agent` header value                  |
| `proto`         | string           | HTTP protocol (`HTTP/1.1`, `HTTP/2.0`, …)  |
| `status`        | numeric          | HTTP response status code                  |
| `bytes`         | numeric          | Response body size in bytes                |
| `response_time` | numeric/optional | Upstream response time in milliseconds (from `us=` log field). Absent on entries that do not carry a response time — conditions on this field never match those entries. |
| `bucket`        | string           | The bucket assigned by a preceding rule in the same pass. Empty string (`""`) if no bucket has been assigned yet. Only `eq`, `neq`, `in`, `not_in` are valid operators. |

---

## Operators

### String operators

Available on: `ip`, `method`, `url`, `referer`, `user_agent`, `proto`, `bucket`

| Op            | Matches when…                                         |
|---------------|-------------------------------------------------------|
| `eq`          | field equals value exactly                            |
| `neq`         | field does not equal value                            |
| `starts_with` | field starts with the given prefix                    |
| `ends_with`   | field ends with the given suffix                      |
| `contains`    | field contains the given substring                    |
| `matches`     | field matches the given regular expression            |
| `in`          | field equals one of a list of values                  |
| `not_in`      | field does not equal any of a list of values          |

> `starts_with`, `ends_with`, `contains`, `matches`, and length operators are **not** valid on `bucket`. Only `eq`, `neq`, `in`, `not_in`.

### Length operators

Available on: `ip`, `method`, `url`, `referer`, `user_agent`, `proto` (not `bucket`)

Compares the **byte length** of the field value numerically.

| Op            | Matches when…                                          |
|---------------|--------------------------------------------------------|
| `len_eq`      | field length equals value                              |
| `len_gt`      | field length is greater than value                     |
| `len_lt`      | field length is less than value                        |
| `len_gte`     | field length is greater than or equal to value         |
| `len_lte`     | field length is less than or equal to value            |
| `len_between` | field length is within `[low, high]` inclusive         |

### Numeric operators

Available on: `status`, `bytes`, `response_time`

| Op        | Matches when…                               |
|-----------|---------------------------------------------|
| `eq`      | field equals value                          |
| `neq`     | field does not equal value                  |
| `gt`      | field is greater than value                 |
| `lt`      | field is less than value                    |
| `gte`     | field is greater than or equal to value     |
| `lte`     | field is less than or equal to value        |
| `between` | field is within `[low, high]` inclusive     |
| `in`      | field equals one of a list of integers      |
| `not_in`  | field does not equal any of a list of integers |

---

## Actions

| Action   | Effect                                                                    |
|----------|---------------------------------------------------------------------------|
| `ignore` | Drop the entry entirely. It is never aggregated. Stops further evaluation. |
| `hide`   | Count hits, visits, and unique IPs, but exclude from the named top-N tables. Multiple `hide` rules accumulate. |
| `sample` | Keep only the given fraction of matching entries (0.0 = drop all, 1.0 = keep all). The first matching `sample` rule applies. |
| `bucket` | Assign a named bucket to the entry for per-bucket stats tracking. The first matching `bucket` rule wins. |

### `ignore`

```yaml
action: ignore
```

### `hide` — selective exclusion

`hide` takes a list of target names. Valid targets:

| Name            | Excludes from                                                        |
|-----------------|----------------------------------------------------------------------|
| `top_urls`      | Top URLs                                                             |
| `top_hosts`     | Top hosts (client IPs)                                               |
| `top_refs`      | Top referrers                                                        |
| `top_agents`    | Top user agents                                                      |
| `top_countries` | Top countries                                                        |
| `timing`        | Response time statistics — global avg/p95 and Slowest Requests. Acts as if `us=` was absent for the matched entry. |

```yaml
- name: "Hide static assets from top tables"
  when:
    - field: url
      op: starts_with
      value: "/static/"
  action:
    hide: [top_urls, top_hosts, top_refs, top_agents, top_countries]

- name: "Exclude known slow endpoints from timing"
  when:
    - field: url
      op: starts_with
      value: "/admin/export/"
  action:
    hide: [timing]
```

### `sample` — probabilistic keep

`sample` takes a float between `0.0` and `1.0`. Matching entries are kept with that probability; the rest are dropped.

- `sample: 1.0` — keep every matching entry (no-op)
- `sample: 0.1` — keep 10% of matching entries
- `sample: 0.0` — drop every matching entry (equivalent to `ignore`)

```yaml
- name: "Sample 5% of health-check traffic"
  when:
    - field: url
      op: eq
      value: "/healthz"
  action:
    sample: 0.05
```

### `bucket` — per-bucket statistics

`bucket` assigns a named label to the entry. The entry is still counted in all global statistics; it is *additionally* counted in a separate per-bucket accumulator. Bucket sub-pages appear in the HTML report under `{period}/buckets/{slug}/`.

Bucket names must be non-empty and must not contain `/` or `\`. Two buckets whose names produce the same URL slug (e.g. `"API Traffic"` and `"api-traffic"` both slug to `api-traffic`) are rejected at startup.

```yaml
- name: "Bucket API traffic"
  when:
    - field: url
      op: starts_with
      value: "/api/"
  action:
    bucket: api
```

#### One bucket per entry

Only the **first** matching `bucket` rule assigns the bucket. Subsequent `bucket` rules that also match are skipped. A one-time warning is logged per skipped rule per run to make this visible.

To avoid unintended shadowing, guard later `bucket` rules with `field: bucket, op: neq`:

```yaml
rules:
  # Tag API first
  - name: "Bucket API"
    when:
      - field: url
        op: starts_with
        value: "/api/"
    action:
      bucket: api

  # Tag errors — but only if not already tagged as API
  # (an API 400 would otherwise silently stay tagged "api", dropping "errors")
  - name: "Bucket errors (non-API)"
    when:
      - field: status
        op: gte
        value: 400
      - field: bucket
        op: neq
        value: api
    action:
      bucket: errors
```

#### Using `field: bucket` in conditions

Because rules fall through, later rules can inspect the bucket assigned by earlier ones using `field: bucket`. This avoids repeating conditions:

```yaml
rules:
  - name: "Bucket API traffic"
    when:
      - field: url
        op: starts_with
        value: "/api/"
    action:
      bucket: api

  # This rule fires for any entry already bucketed "api" — no URL condition needed
  - name: "Hide API from URL tables"
    when:
      - field: bucket
        op: eq
        value: api
    action:
      hide: [top_urls]
```

`field: bucket` evaluates to `""` (empty string) on entries that have not yet been assigned a bucket, so `op: eq` with any non-empty bucket name will not match unassigned entries.

---

## Operator examples

### `eq` / `neq`

```yaml
- field: status
  op: eq
  value: 200

- field: method
  op: neq
  value: GET
```

### `starts_with` / `ends_with`

```yaml
- field: url
  op: starts_with
  value: "/api/"

- field: url
  op: ends_with
  value: ".php"
```

### `contains`

```yaml
- field: user_agent
  op: contains
  value: "bot"
```

### `matches` (regular expression)

> **Warning:** `matches` runs a full regex engine on every log entry and is significantly slower than the other string operators. Only use it when no simpler operator will do. In particular:
> - `^/foo` → use `starts_with: /foo`
> - `/foo$` → use `ends_with: /foo`
> - `/foo/` → use `contains: /foo/`

The pattern is a full [Rust regex](https://docs.rs/regex/latest/regex/#syntax).

```yaml
- field: url
  op: matches
  value: "^/admin/.*\\.php$"
```

### `in` / `not_in`

For numeric fields (`status`, `bytes`, `response_time`), values in the list must be integers:

```yaml
- field: status
  op: in
  value: [301, 302, 303, 307, 308]
```

For string fields, values are strings:

```yaml
- field: method
  op: not_in
  value: [GET, HEAD, OPTIONS]
```

### `len_between` (inclusive)

```yaml
- field: user_agent
  op: len_between
  value: [10, 500]
```

### `between` (numeric, inclusive)

```yaml
- field: status
  op: between
  value: [500, 599]

- field: response_time
  op: between
  value: [5000, 30000]   # 5 000 ms – 30 000 ms
```

---

## Performance notes

**Put cheap / most-selective conditions first.** `all` and `any` short-circuit: the engine stops evaluating conditions as soon as the result is known. A cheap `status eq 301` check before an `url starts_with` check saves the string comparison for every non-301 entry.

**`in` / `not_in` use hash sets.** Lookup is O(1) regardless of list length, so a blocklist of 1 000 user-agent substrings costs the same as a list of 3.

**`matches` (regex) is the most expensive operator.** Prefer `starts_with`, `ends_with`, or `contains` when any of those will do.

**`response_time` conditions silently skip entries with no response time logged.** If your log format does not include `us=`, every condition on `response_time` evaluates to no-match — the rule does not fire for those entries.

**Bucket rules add a small constant overhead per matched entry** to update the per-bucket accumulators. This is negligible for typical bucket counts (2–20 buckets).

---

## Full example

```yaml
rules:
  # ── Noise suppression ─────────────────────────────────────────────────────

  - name: "Drop PHP probes"
    when:
      - field: url
        op: ends_with
        value: ".php"
    action: ignore

  - name: "Drop known scrapers"
    when:
      any:
        - field: user_agent
          op: contains
          value: "Googlebot"
        - field: user_agent
          op: contains
          value: "bingbot"
        - field: user_agent
          op: contains
          value: "AhrefsBot"
    action: ignore

  - name: "Sample health-check noise"
    when:
      - field: url
        op: eq
        value: "/healthz"
    action:
      sample: 0.05

  # ── Bucketing ─────────────────────────────────────────────────────────────

  - name: "Bucket API traffic"
    when:
      - field: url
        op: starts_with
        value: "/api/"
    action:
      bucket: api

  - name: "Bucket static assets"
    when:
      any:
        - field: url
          op: starts_with
          value: "/static/"
        - field: url
          op: starts_with
          value: "/assets/"
    action:
      bucket: static

  # Tag errors that aren't already tagged as something else
  - name: "Bucket errors"
    when:
      - field: status
        op: gte
        value: 400
      - field: bucket
        op: eq
        value: ""
    action:
      bucket: errors

  # ── Hide rules (use field: bucket to avoid repeating conditions) ──────────

  - name: "Hide static assets from top tables"
    when:
      - field: bucket
        op: eq
        value: static
    action:
      hide: [top_urls, top_hosts, top_refs, top_agents, top_countries]

  - name: "Exclude admin exports from timing"
    when:
      - field: url
        op: starts_with
        value: "/admin/export/"
    action:
      hide: [timing]
```
