use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use super::messages::{pop_blocking, push_blocking, LoaderMsg, OwnedLogEntry, ParserMsg};
use super::PARSER_BATCH_SIZE;

pub(super) fn run_parser(
    mut rx: rtrb::Consumer<LoaderMsg>,
    mut tx: rtrb::Producer<ParserMsg>,
    lines_done: Arc<AtomicU64>,
) {
    let mut entry_batch: Vec<OwnedLogEntry> = Vec::with_capacity(PARSER_BATCH_SIZE);
    let mut current_offset: u64 = 0;

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
                for line in batch {
                    if let Some(entry) = OwnedLogEntry::parse(line) {
                        entry_batch.push(entry);

                        if entry_batch.len() >= PARSER_BATCH_SIZE {
                            lines_done.fetch_add(entry_batch.len() as u64, Ordering::Relaxed);
                            push_blocking(
                                &mut tx,
                                ParserMsg::Entries {
                                    batch: std::mem::take(&mut entry_batch),
                                    current_offset,
                                },
                            );
                            entry_batch = Vec::with_capacity(PARSER_BATCH_SIZE);
                        }
                    } else {
                        // If parsing fails, we can choose to log it, count it, or ignore it.
                        // For now, we'll just ignore malformed lines.
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
                    lines_done.fetch_add(entry_batch.len() as u64, Ordering::Relaxed);
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
                    lines_done.fetch_add(entry_batch.len() as u64, Ordering::Relaxed);
                    push_blocking(
                        &mut tx,
                        ParserMsg::Entries {
                            batch: std::mem::take(&mut entry_batch),
                            current_offset,
                        },
                    );
                }
                push_blocking(&mut tx, ParserMsg::Done);
                return;
            }
        }
    }
}
