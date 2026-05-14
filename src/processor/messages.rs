pub use crate::parser::OwnedLogEntry;

pub(super) enum LoaderMsg {
    FileStart {
        file_idx: usize,
    },
    Lines {
        batch: Vec<String>,
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

pub(super) enum ParserMsg {
    FileStart {
        file_idx: usize,
    },
    Entries {
        batch: Vec<OwnedLogEntry>,
        /// Same meaning as LoaderMsg::Lines::current_offset.
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
pub(super) fn push_blocking<T>(tx: &mut rtrb::Producer<T>, mut item: T) {
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
pub(super) fn pop_blocking<T>(rx: &mut rtrb::Consumer<T>) -> T {
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
