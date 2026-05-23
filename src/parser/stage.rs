// Pipeline parser thread: receives raw lines from the loader, parses them, applies UA
// classification, bot filtering, and rules, then forwards batches to the aggregator.

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::aggregator::messages::{
    pop_blocking, push_blocking, LoaderMsg, ParsedEntry, ParserMsg,
};
use crate::aggregator::{ProgressState, PARSER_BATCH_SIZE};
use crate::parser::OwnedLogEntry;
use crate::rules::{Action, HideMask, SharedRuleSet};
use crate::ua::UaParser;
use rand::Rng as _;

pub(crate) struct RuleStats {
    pub ignored: u64,
    pub hidden: u64,
}

pub(crate) fn run_parser(
    mut rx: rtrb::Consumer<LoaderMsg>,
    mut tx: rtrb::Producer<ParserMsg>,
    ps: Arc<ProgressState>,
    mut ua: UaParser,
    bot_filter: bool,
    rule_set: Option<SharedRuleSet>,
) -> (BTreeMap<Arc<str>, RuleStats>, u64) {
    let mut entry_batch: Vec<(ParsedEntry, u64)> = Vec::with_capacity(PARSER_BATCH_SIZE);
    let mut current_offset: u64 = 0;
    let mut rule_stats: BTreeMap<Arc<str>, RuleStats> = BTreeMap::new();
    let mut bot_filtered: u64 = 0;

    loop {
        match pop_blocking(&mut rx) {
            LoaderMsg::FileStart { file_idx } => {
                push_blocking(&mut tx, ParserMsg::FileStart { file_idx });
            }

            LoaderMsg::Lines {
                batch,
                current_offset: offset,
            } => {
                current_offset = offset;
                for (line, line_start) in batch {
                    if let Some(entry) = OwnedLogEntry::parse(line) {
                        let ua_result = ua.parse(entry.user_agent());
                        if bot_filter && ua_result.is_bot {
                            bot_filtered += 1;
                            ps.lines_done.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        let hidden = if let Some(rs) = &rule_set {
                            match rs.apply(&entry) {
                                Some((name, Action::Ignore)) => {
                                    rule_stats
                                        .entry(Arc::clone(name))
                                        .or_insert(RuleStats {
                                            ignored: 0,
                                            hidden: 0,
                                        })
                                        .ignored += 1;
                                    ps.lines_done.fetch_add(1, Ordering::Relaxed);
                                    continue;
                                }
                                Some((name, Action::Hide(mask))) => {
                                    rule_stats
                                        .entry(Arc::clone(name))
                                        .or_insert(RuleStats {
                                            ignored: 0,
                                            hidden: 0,
                                        })
                                        .hidden += 1;
                                    *mask
                                }
                                Some((name, Action::Sample(rate))) => {
                                    if rand::thread_rng().gen::<f64>() >= *rate {
                                        rule_stats
                                            .entry(Arc::clone(name))
                                            .or_insert(RuleStats {
                                                ignored: 0,
                                                hidden: 0,
                                            })
                                            .ignored += 1;
                                        ps.lines_done.fetch_add(1, Ordering::Relaxed);
                                        continue;
                                    }
                                    HideMask::NONE
                                }
                                None => HideMask::NONE,
                            }
                        } else {
                            HideMask::NONE
                        };
                        entry_batch.push((
                            ParsedEntry {
                                entry,
                                ua_family: ua_result.family,
                                hidden,
                            },
                            line_start,
                        ));

                        if entry_batch.len() >= PARSER_BATCH_SIZE {
                            ps.lines_done
                                .fetch_add(entry_batch.len() as u64, Ordering::Relaxed);
                            push_blocking(
                                &mut tx,
                                ParserMsg::Entries {
                                    batch: std::mem::take(&mut entry_batch),
                                    current_offset,
                                },
                            );
                            entry_batch = Vec::with_capacity(PARSER_BATCH_SIZE);
                        }
                    }
                }
            }

            LoaderMsg::FileDone {
                file_idx,
                final_offset,
                completed,
            } => {
                // Flush any partial entry batch before signalling file done.
                if !entry_batch.is_empty() {
                    ps.lines_done
                        .fetch_add(entry_batch.len() as u64, Ordering::Relaxed);
                    push_blocking(
                        &mut tx,
                        ParserMsg::Entries {
                            batch: std::mem::take(&mut entry_batch),
                            current_offset,
                        },
                    );
                    entry_batch = Vec::with_capacity(PARSER_BATCH_SIZE);
                }
                push_blocking(
                    &mut tx,
                    ParserMsg::FileDone {
                        file_idx,
                        final_offset,
                        completed,
                    },
                );
            }

            LoaderMsg::Done => {
                // Flush any remaining entries (shouldn't happen after a FileDone, but be safe).
                if !entry_batch.is_empty() {
                    ps.lines_done
                        .fetch_add(entry_batch.len() as u64, Ordering::Relaxed);
                    push_blocking(
                        &mut tx,
                        ParserMsg::Entries {
                            batch: std::mem::take(&mut entry_batch),
                            current_offset,
                        },
                    );
                }
                push_blocking(&mut tx, ParserMsg::Done);
                return (rule_stats, bot_filtered);
            }
        }
    }
}
