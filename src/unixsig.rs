// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! SIGINT and SIGTERM handling with C library calls.

#![allow(unsafe_code)]

const SIGINT: i32 = 2;
const SIGTERM: i32 = 15;
const SIG_IGN: usize = 1;

extern "C" {
    fn signal(sig: i32, handler: usize) -> usize;
    fn _exit(code: i32) -> !;
    fn write(fd: i32, buf: *const u8, count: usize) -> isize;
}

extern "C" fn handler(_sig: i32) {
    crate::errhnd::process_signal();
}

pub fn set_handlers(enable: bool) {
    let h = if enable { handler as extern "C" fn(i32) as usize } else { SIG_IGN };
    // SAFETY: handler only updates atomic flags or calls _exit, which are
    // async-signal-safe.
    unsafe {
        signal(SIGINT, h);
        signal(SIGTERM, h);
    }
}

/// Write message to stdout directly, safe to call from signal handler.
pub fn write_stdout(msg: &str) {
    // SAFETY: the buffer is valid for msg.len() bytes, write is
    // async-signal-safe.
    unsafe {
        write(1, msg.as_ptr(), msg.len());
    }
}

/// Exit immediately without cleanup, safe to call from signal handler.
pub fn exit_now(code: i32) -> ! {
    // SAFETY: _exit is async-signal-safe and never returns.
    unsafe { _exit(code) }
}
