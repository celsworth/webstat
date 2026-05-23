use std::sync::atomic::{AtomicU8, Ordering};

use crate::progress::clear_progress_line;
use crate::util::current_log_timestamp;

static LOG_VERBOSE: AtomicU8 = AtomicU8::new(0);
static LOG_DEBUG: AtomicU8 = AtomicU8::new(0);

pub fn init(verbose: bool, debug: u8) {
    LOG_VERBOSE.store(verbose as u8, Ordering::Relaxed);
    LOG_DEBUG.store(debug, Ordering::Relaxed);
}

pub fn verbose() -> bool {
    LOG_VERBOSE.load(Ordering::Relaxed) != 0
}

pub fn debug_level() -> u8 {
    LOG_DEBUG.load(Ordering::Relaxed)
}

pub fn log(msg: &str) {
    if verbose() {
        emit(msg);
    }
}

pub fn log_debug(msg: &str) {
    log_debug_at(1, msg);
}

pub fn log_debug_at(level: u8, msg: &str) {
    if LOG_DEBUG.load(Ordering::Relaxed) >= level {
        emit(msg);
    }
}

fn emit(msg: &str) {
    clear_progress_line();
    let ts = current_log_timestamp();
    eprintln!("{ts} {msg}");
}
