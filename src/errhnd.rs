// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Error handling and exit codes. Fatal errors unwind the stack with a
//! `RarExit` payload, which is caught at the top level.

use crate::ui::{ui_alarm, ui_msg, UiAlarm, UiMsg};
use std::cell::RefCell;
#[cfg(unix)]
use std::sync::atomic::AtomicU32;
use std::sync::atomic::{AtomicBool, Ordering};

pub const RARX_SUCCESS: i32 = 0;
pub const RARX_WARNING: i32 = 1;
pub const RARX_FATAL: i32 = 2;
pub const RARX_CRC: i32 = 3;
pub const RARX_LOCK: i32 = 4;
pub const RARX_WRITE: i32 = 5;
pub const RARX_OPEN: i32 = 6;
pub const RARX_USERERROR: i32 = 7;
pub const RARX_MEMORY: i32 = 8;
pub const RARX_CREATE: i32 = 9;
pub const RARX_NOFILES: i32 = 10;
pub const RARX_BADPWD: i32 = 11;
pub const RARX_READ: i32 = 12;
pub const RARX_BADARC: i32 = 13;
pub const RARX_DELETE: i32 = 14;
pub const RARX_USERBREAK: i32 = 255;

/// Panic payload used to abort processing with an exit code.
#[derive(Debug, Clone, Copy)]
pub struct RarExit(pub i32);

struct ErrorHandler {
    exit_code: i32,
    err_count: u32,
    silent: bool,
    read_err_ignore_all: bool,
    last_os_error: Option<String>,
}

thread_local! {
    static EH: RefCell<ErrorHandler> = const { RefCell::new(ErrorHandler {
        exit_code: RARX_SUCCESS,
        err_count: 0,
        silent: false,
        read_err_ignore_all: false,
        last_os_error: None,
    }) };
}

pub fn clean() {
    EH.with(|e| {
        let mut e = e.borrow_mut();
        e.exit_code = RARX_SUCCESS;
        e.err_count = 0;
        e.silent = false;
        e.read_err_ignore_all = false;
    });
}

pub fn set_silent(mode: bool) {
    EH.with(|e| e.borrow_mut().silent = mode);
}

pub fn is_silent() -> bool {
    EH.with(|e| e.borrow().silent)
}

pub fn get_error_code() -> i32 {
    EH.with(|e| e.borrow().exit_code)
}

pub fn get_error_count() -> u32 {
    EH.with(|e| e.borrow().err_count)
}

pub fn set_error_code(code: i32) {
    EH.with(|e| {
        let mut e = e.borrow_mut();
        match code {
            RARX_WARNING | RARX_USERBREAK => {
                if e.exit_code == RARX_SUCCESS {
                    e.exit_code = code;
                }
            }
            RARX_CRC => {
                if e.exit_code != RARX_BADPWD && e.exit_code != RARX_OPEN {
                    e.exit_code = code;
                }
            }
            RARX_FATAL => {
                if e.exit_code == RARX_SUCCESS || e.exit_code == RARX_WARNING {
                    e.exit_code = RARX_FATAL;
                }
            }
            _ => e.exit_code = code,
        }
        e.err_count += 1;
    });
}

/// Remember the last OS error to report it with `sys_err_msg`.
pub fn set_os_error(err: &std::io::Error) {
    let mut s = err.to_string();
    if let Some(p) = s.find(" (os error") {
        s.truncate(p);
    }
    EH.with(|e| e.borrow_mut().last_os_error = Some(s));
}

pub fn clear_os_error() {
    EH.with(|e| e.borrow_mut().last_os_error = None);
}

pub fn get_sys_err_msg() -> Option<String> {
    EH.with(|e| e.borrow().last_os_error.clone())
}

pub fn sys_err_msg() {
    if let Some(m) = get_sys_err_msg() {
        ui_msg(UiMsg::SysErrMsg(m));
    }
}

/// Abort processing with the specified exit code.
pub fn exit(code: i32) -> ! {
    ui_alarm(UiAlarm::Error);
    throw(code)
}

pub fn throw(code: i32) -> ! {
    if code != RARX_SUCCESS {
        if code == RARX_USERERROR {
            crate::consio::mprintf("\n");
        } else {
            crate::consio::mprintf(&crate::wfmt!("\n%s\n", crate::loclang::MProgAborted));
        }
    }
    set_error_code(code);
    std::panic::resume_unwind(Box::new(RarExit(code)))
}

pub fn memory_error() -> ! {
    memory_error_msg();
    exit(RARX_MEMORY)
}

/// Out of memory condition: report and abort without
/// "Program aborted" message.
pub fn bad_alloc() -> ! {
    memory_error_msg();
    std::panic::resume_unwind(Box::new(RarExit(RARX_MEMORY)))
}

pub fn memory_error_msg() {
    ui_msg(UiMsg::Memory);
    set_error_code(RARX_MEMORY);
}

pub fn open_error(name: &str) -> ! {
    open_error_msg("", name);
    exit(RARX_OPEN)
}

pub fn open_error_msg(arc: &str, name: &str) {
    ui_msg(UiMsg::FileOpen(arc.into(), name.into()));
    sys_err_msg();
    set_error_code(RARX_OPEN);
    // Keep responsive if many files cannot be opened.
    wait();
}

pub fn close_error(name: &str) {
    ui_msg(UiMsg::FileClose(name.into()));
    sys_err_msg();
    set_error_code(RARX_FATAL);
}

pub fn read_error(name: &str) -> ! {
    read_error_msg("", name);
    exit(RARX_READ)
}

pub fn read_error_msg(arc: &str, name: &str) {
    ui_msg(UiMsg::FileRead(arc.into(), name.into()));
    sys_err_msg();
    set_error_code(RARX_READ);
}

/// Returns (ignore, retry, quit).
pub fn ask_repeat_read(name: &str) -> (bool, bool, bool) {
    set_error_code(RARX_READ);
    if !is_silent() {
        ui_msg(UiMsg::FileRead(String::new(), name.into()));
        sys_err_msg();
        if EH.with(|e| e.borrow().read_err_ignore_all) {
            return (true, false, false);
        }
        let (ignore, all, retry, quit) = crate::ui::ui_ask_repeat_read(name);
        if all {
            EH.with(|e| e.borrow_mut().read_err_ignore_all = true);
            return (true, retry, quit);
        }
        return (ignore, retry, quit);
    }
    (true, false, false)
}

pub fn write_error(arc: &str, name: &str) -> ! {
    write_error_msg(arc, name);
    exit(RARX_WRITE)
}

pub fn write_error_msg(arc: &str, name: &str) {
    ui_msg(UiMsg::FileWrite(arc.into(), name.into()));
    sys_err_msg();
    set_error_code(RARX_WRITE);
}

pub fn ask_repeat_write(name: &str, disk_full: bool) -> bool {
    if !is_silent() {
        sys_err_msg();
        return crate::ui::ui_ask_repeat_write(name, disk_full);
    }
    false
}

pub fn seek_error(name: &str) -> ! {
    ui_msg(UiMsg::FileSeek(name.into()));
    sys_err_msg();
    exit(RARX_FATAL)
}

pub fn general_err_msg(msg: &str) {
    ui_msg(UiMsg::GeneralErrMsg(msg.into()));
    sys_err_msg();
}

pub fn create_error_msg(arc: &str, name: &str) {
    ui_msg(UiMsg::FileCreate(arc.into(), name.into()));
    sys_err_msg();
    set_error_code(RARX_CREATE);
}

pub fn arc_broken_msg(arc: &str) {
    ui_msg(UiMsg::ArcBroken(arc.into()));
    set_error_code(RARX_CRC);
}

pub fn checksum_failed_msg(arc: &str, name: &str) {
    ui_msg(UiMsg::Checksum(arc.into(), name.into()));
    set_error_code(RARX_CRC);
}

pub fn unknown_method_msg(arc: &str, name: &str) {
    ui_msg(UiMsg::UnknownMethod(arc.into(), name.into()));
    set_error_code(RARX_FATAL);
}

static USER_BREAK: AtomicBool = AtomicBool::new(false);
static MAIN_EXIT: AtomicBool = AtomicBool::new(false);
static DISABLE_SHUTDOWN: AtomicBool = AtomicBool::new(false);
#[cfg(unix)]
static BREAK_COUNT: AtomicU32 = AtomicU32::new(0);

pub fn user_break() -> bool {
    USER_BREAK.load(Ordering::SeqCst)
}

pub fn is_shutdown_enabled() -> bool {
    !DISABLE_SHUTDOWN.load(Ordering::SeqCst)
}

/// Main thread completed and does not need a break handler to wait.
pub fn set_main_exit() {
    MAIN_EXIT.store(true, Ordering::SeqCst);
}

/// Ctrl+C or termination request handler.
pub fn process_signal() {
    USER_BREAK.store(true, Ordering::SeqCst);
    DISABLE_SHUTDOWN.store(true, Ordering::SeqCst);
    // Windows handler runs in a separate thread, so it can print and
    // let the main thread to delete incomplete files and quit.
    #[cfg(windows)]
    {
        crate::consio::mprintf(crate::loclang::MBreak);
        for _ in 0..50 {
            if MAIN_EXIT.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        std::process::exit(RARX_USERBREAK);
    }
    // Unix signal handler interrupts the main code, so only set the flag
    // and let wait() close files and quit. Exit immediately if user
    // continues to press Ctrl+C.
    #[cfg(unix)]
    {
        crate::unixsig::write_stdout(crate::loclang::MBreak);
        if BREAK_COUNT.fetch_add(1, Ordering::SeqCst) >= 1 {
            crate::unixsig::exit_now(RARX_USERBREAK);
        }
    }
}

/// Install or remove Ctrl+C and termination handlers.
pub fn set_signal_handlers(enable: bool) {
    #[cfg(windows)]
    crate::win32::set_ctrl_handler(enable);
    #[cfg(unix)]
    crate::unixsig::set_handlers(enable);
    #[cfg(not(any(unix, windows)))]
    let _ = enable;
}

/// Called periodically during long operations. Quits on user break and
/// makes pauses requested by -ri switch.
pub fn wait() {
    if user_break() {
        exit(RARX_USERBREAK);
    }
    #[cfg(windows)]
    {
        crate::winsys::wait();
        crate::win32::keep_system_awake();
    }
}

/// Run `f` catching `RarExit` unwinding. Other panics are reported as
/// fatal errors. Returns the final error code.
pub fn run_catching<F: FnOnce()>(f: F) -> i32 {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if info.payload().downcast_ref::<RarExit>().is_none() {
            prev(info);
        }
    }));
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(()) => {}
        Err(e) => {
            if let Some(RarExit(code)) = e.downcast_ref::<RarExit>() {
                set_error_code(*code);
            } else {
                set_error_code(RARX_FATAL);
            }
        }
    }
    get_error_code()
}
