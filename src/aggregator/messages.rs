// Channel message types for the three-stage pipeline: LoaderMsg (loader→parser),
// ParserMsg / ParsedEntry (parser→aggregator), and the push/pop blocking helpers.

use crate::parser::OwnedLogEntry;
use crate::rules::HideMask;
use std::sync::Arc;

/// A parsed log entry with its UA family already resolved.
/// Bot entries are filtered out in the parser stage and never reach the aggregator.
pub(crate) struct ParsedEntry {
    pub entry: OwnedLogEntry,
    pub ua_family: Arc<str>,
    /// Which top-N tables to exclude this entry from (zero = not hidden from anything).
    pub hidden: HideMask,
}

pub(crate) enum LoaderMsg {
    FileStart {
        file_idx: usize,
    },
    Lines {
        /// Each line paired with its start byte offset in the (decoded) file.
        batch: Vec<(String, u64)>,
        /// Byte offset after the last line in this batch.
        /// Plain files: absolute file position; compressed: total decoded bytes.
        current_offset: u64,
    },
    FileDone {
        file_idx: usize,
        final_offset: u64,
        completed: bool,
    },
    Done,
}

pub(crate) enum ParserMsg {
    FileStart {
        file_idx: usize,
    },
    Entries {
        /// Each parsed entry paired with its start byte offset in the (decoded) file.
        batch: Vec<(ParsedEntry, u64)>,
        /// Byte offset after the last entry in this batch.
        current_offset: u64,
    },
    FileDone {
        file_idx: usize,
        final_offset: u64,
        completed: bool,
    },
    Done,
}

/// Spin-yield loop to push an item into a bounded rtrb ring buffer.
/// Returns only when the push succeeds.
pub(crate) fn push_blocking<T>(tx: &mut rtrb::Producer<T>, mut item: T) {
    let mut spins = 0u32;
    loop {
        match tx.push(item) {
            Ok(()) => return,
            Err(rtrb::PushError::Full(val)) => {
                item = val;
                spins += 1;
                if spins < 64 {
                    std::hint::spin_loop();
                } else {
                    spins = 0;
                    std::thread::yield_now();
                }
            }
        }
    }
}

/// Spin-yield loop to pop an item from a bounded rtrb ring buffer.
/// Returns only when an item is available.
pub(crate) fn pop_blocking<T>(rx: &mut rtrb::Consumer<T>) -> T {
    let mut spins = 0u32;
    loop {
        match rx.pop() {
            Ok(val) => return val,
            Err(rtrb::PopError::Empty) => {
                spins += 1;
                if spins < 64 {
                    std::hint::spin_loop();
                } else {
                    spins = 0;
                    std::thread::yield_now();
                }
            }
        }
    }
}
