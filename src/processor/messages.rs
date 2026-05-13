use std::ops::Range;

/// Fully-owned parsed log entry.
///
/// Instead of allocating individual Strings for every field,
/// we keep one owned backing line and store spans into it.
///
/// This is dramatically more allocation/cache efficient than:
///
///   ip: String,
///   path: String,
///   ...
///
#[derive(Debug)]
pub struct OwnedLogEntry {
    raw: Box<str>,

    ip: Range<usize>,
    time: Range<usize>,
    method: Range<usize>,
    path: Range<usize>,
    proto: Range<usize>,
    referer: Range<usize>,
    user_agent: Range<usize>,

    pub month_num: u8,
    pub status: u16,
    pub bytes: u64,
}

impl OwnedLogEntry {
    #[inline]
    pub fn parse(line: String) -> Option<Self> {
        let raw: Box<str> = line.into_boxed_str();
        let parsed = crate::parser::parse_line(&raw)?;

        Some(Self {
            ip: parsed.ip,
            time: parsed.time,
            method: parsed.method,
            path: parsed.path,
            proto: parsed.proto,
            referer: parsed.referer,
            user_agent: parsed.user_agent,

            month_num: parsed.month_num,
            status: parsed.status,
            bytes: parsed.bytes,

            raw,
        })
    }
    #[inline]
    fn slice(&self, r: Range<usize>) -> &str {
        &self.raw[r]
    }

    pub fn ip(&self) -> &str {
        self.slice(self.ip.clone())
    }

    pub fn path(&self) -> &str {
        self.slice(self.path.clone())
    }

    pub fn method(&self) -> &str {
        self.slice(self.method.clone())
    }

    pub fn proto(&self) -> &str {
        self.slice(self.proto.clone())
    }

    pub fn referer(&self) -> &str {
        self.slice(self.referer.clone())
    }

    pub fn user_agent(&self) -> &str {
        self.slice(self.user_agent.clone())
    }

    pub fn time_str(&self) -> &str {
        self.slice(self.time.clone())
    }
}

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
