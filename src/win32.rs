// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Windows API declarations and safe wrappers. This is the only module
//! with unsafe code. Every wrapper converts strings and checks results,
//! so the rest of the program uses only safe functions.

#![allow(unsafe_code)]
#![allow(clippy::upper_case_acronyms)]

use std::ffi::c_void;
use std::ptr::{null, null_mut};

type HANDLE = *mut c_void;
type BOOL = i32;
const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct FILETIME {
    low: u32,
    high: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct SYSTEMTIME {
    year: u16,
    month: u16,
    day_of_week: u16,
    day: u16,
    hour: u16,
    minute: u16,
    second: u16,
    milliseconds: u16,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct LUID {
    low: u32,
    high: i32,
}

#[repr(C)]
struct TOKEN_PRIVILEGES {
    count: u32,
    luid: LUID,
    attributes: u32,
}

type CtrlHandler = unsafe extern "system" fn(u32) -> BOOL;

#[link(name = "kernel32")]
extern "system" {
    fn GetLastError() -> u32;
    fn CloseHandle(h: HANDLE) -> BOOL;
    fn SetConsoleCtrlHandler(handler: Option<CtrlHandler>, add: BOOL) -> BOOL;
    fn GetStdHandle(n: u32) -> HANDLE;
    fn GetConsoleMode(h: HANDLE, mode: *mut u32) -> BOOL;
    fn SetConsoleMode(h: HANDLE, mode: u32) -> BOOL;
    fn GetFileAttributesW(name: *const u16) -> u32;
    fn SetFileAttributesW(name: *const u16, attr: u32) -> BOOL;
    fn CreateFileW(name: *const u16, access: u32, share: u32, sa: *const c_void, disp: u32, flags: u32, template: HANDLE) -> HANDLE;
    fn DeviceIoControl(h: HANDLE, code: u32, inb: *const c_void, insize: u32, outb: *mut c_void, outsize: u32, ret: *mut u32, ov: *mut c_void) -> BOOL;
    fn GetACP() -> u32;
    fn GetOEMCP() -> u32;
    fn MultiByteToWideChar(cp: u32, flags: u32, src: *const u8, srclen: i32, dst: *mut u16, dstlen: i32) -> i32;
    fn WideCharToMultiByte(cp: u32, flags: u32, src: *const u16, srclen: i32, dst: *mut u8, dstlen: i32, def: *const u8, used: *mut BOOL) -> i32;
    fn GetCurrentProcess() -> HANDLE;
    fn GetCurrentThread() -> HANDLE;
    fn SetPriorityClass(h: HANDLE, class: u32) -> BOOL;
    fn SetThreadPriority(h: HANDLE, prio: i32) -> BOOL;
    fn CreateEventW(sa: *const c_void, manual: BOOL, initial: BOOL, name: *const u16) -> HANDLE;
    fn SetThreadExecutionState(flags: u32) -> u32;
    fn FileTimeToSystemTime(ft: *const FILETIME, st: *mut SYSTEMTIME) -> BOOL;
    fn SystemTimeToFileTime(st: *const SYSTEMTIME, ft: *mut FILETIME) -> BOOL;
    fn SystemTimeToTzSpecificLocalTime(tz: *const c_void, utc: *const SYSTEMTIME, local: *mut SYSTEMTIME) -> BOOL;
    fn TzSpecificLocalTimeToSystemTime(tz: *const c_void, local: *const SYSTEMTIME, utc: *mut SYSTEMTIME) -> BOOL;
}

#[link(name = "advapi32")]
extern "system" {
    fn SetFileSecurityW(name: *const u16, si: u32, sd: *const c_void) -> BOOL;
    fn OpenProcessToken(process: HANDLE, access: u32, token: *mut HANDLE) -> BOOL;
    fn LookupPrivilegeValueW(system: *const u16, name: *const u16, luid: *mut LUID) -> BOOL;
    fn AdjustTokenPrivileges(token: HANDLE, disable_all: BOOL, new: *const TOKEN_PRIVILEGES, len: u32, prev: *mut c_void, ret: *mut u32) -> BOOL;
    fn AllocateAndInitializeSid(
        auth: *const [u8; 6],
        count: u8,
        a0: u32,
        a1: u32,
        a2: u32,
        a3: u32,
        a4: u32,
        a5: u32,
        a6: u32,
        a7: u32,
        sid: *mut *mut c_void,
    ) -> BOOL;
    fn CheckTokenMembership(token: HANDLE, sid: *mut c_void, is_member: *mut BOOL) -> BOOL;
    fn FreeSid(sid: *mut c_void) -> *mut c_void;
}

#[link(name = "user32")]
extern "system" {
    fn ExitWindowsEx(flags: u32, reason: u32) -> BOOL;
}

#[link(name = "powrprof")]
extern "system" {
    fn SetSuspendState(hibernate: u8, force: u8, wake_disabled: u8) -> u8;
}

pub const ERROR_ACCESS_DENIED: u32 = 5;
pub const ERROR_PRIVILEGE_NOT_HELD: u32 = 1314;

/// Zero terminated UTF-16 file name. Long paths get the \\?\ prefix,
/// so they are not limited by MAX_PATH.
fn wide_name(name: &str) -> Vec<u16> {
    let mut n = name.to_string();
    if n.encode_utf16().count() >= 260 && !n.starts_with("\\\\?\\") {
        if let Ok(abs) = std::path::absolute(&n) {
            let a = abs.to_string_lossy().into_owned();
            n = match a.strip_prefix("\\\\") {
                Some(unc) => format!("\\\\?\\UNC\\{}", unc),
                None => format!("\\\\?\\{}", a),
            };
        }
    }
    wide(&n)
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn last_error() -> u32 {
    // SAFETY: no arguments, reads thread error state.
    unsafe { GetLastError() }
}

/// Windows error as io::Error, so it can be reported like std errors.
pub fn os_error(code: u32) -> std::io::Error {
    std::io::Error::from_raw_os_error(code as i32)
}

struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle was returned by a successful open call.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

const GENERIC_READ: u32 = 0x80000000;
const GENERIC_WRITE: u32 = 0x40000000;
const OPEN_EXISTING: u32 = 3;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x02000000;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x00200000;

fn open_existing(name: &str, access: u32, share: u32, flags: u32) -> Result<Handle, u32> {
    let w = wide_name(name);
    // SAFETY: w is a zero terminated string valid during the call.
    let h = unsafe { CreateFileW(w.as_ptr(), access, share, null(), OPEN_EXISTING, flags, null_mut()) };
    if h == INVALID_HANDLE_VALUE {
        Err(last_error())
    } else {
        Ok(Handle(h))
    }
}

// Console.

const CTRL_LOGOFF_EVENT: u32 = 5;

unsafe extern "system" fn ctrl_handler(sig: u32) -> BOOL {
    // Allow a console program run as a service to continue after logoff.
    if sig == CTRL_LOGOFF_EVENT {
        return 1;
    }
    crate::errhnd::process_signal();
    1
}

/// Install or remove Ctrl+C, Ctrl+Break and console close handler.
pub fn set_ctrl_handler(enable: bool) {
    let h: Option<CtrlHandler> = if enable { Some(ctrl_handler) } else { None };
    // SAFETY: handler is a static function with the required signature.
    unsafe {
        SetConsoleCtrlHandler(h, 1);
    }
}

const STD_INPUT_HANDLE: u32 = -10i32 as u32;
const ENABLE_ECHO_INPUT: u32 = 4;

/// Enable or disable console input echo. Returns false if stdin is not
/// a console.
pub fn set_console_echo(on: bool) -> bool {
    // SAFETY: standard handle is owned by the process and not closed here,
    // mode points to a local variable.
    unsafe {
        let h = GetStdHandle(STD_INPUT_HANDLE);
        let mut mode = 0u32;
        if h.is_null() || h == INVALID_HANDLE_VALUE || GetConsoleMode(h, &mut mode) == 0 {
            return false;
        }
        let mode = if on { mode | ENABLE_ECHO_INPUT } else { mode & !ENABLE_ECHO_INPUT };
        SetConsoleMode(h, mode) != 0
    }
}

// File attributes, compression and security.

pub fn get_file_attr(name: &str) -> Option<u32> {
    let w = wide_name(name);
    // SAFETY: w is a zero terminated string valid during the call.
    let a = unsafe { GetFileAttributesW(w.as_ptr()) };
    if a == u32::MAX {
        None
    } else {
        Some(a)
    }
}

pub fn set_file_attr(name: &str, attr: u32) -> Result<(), u32> {
    let w = wide_name(name);
    // SAFETY: w is a zero terminated string valid during the call.
    if unsafe { SetFileAttributesW(w.as_ptr(), attr) } != 0 {
        Ok(())
    } else {
        Err(last_error())
    }
}

const FSCTL_SET_COMPRESSION: u32 = 0x9C040;
const FSCTL_SET_REPARSE_POINT: u32 = 0x900A4;
const COMPRESSION_FORMAT_DEFAULT: u16 = 1;

/// Set NTFS compression for file or directory.
pub fn set_compression(name: &str) -> bool {
    let h = match open_existing(name, GENERIC_READ | GENERIC_WRITE, 3, FILE_FLAG_BACKUP_SEMANTICS) {
        Ok(h) => h,
        Err(_) => return false,
    };
    let state = COMPRESSION_FORMAT_DEFAULT;
    let mut ret = 0u32;
    // SAFETY: input buffer points to a local u16 of the declared size.
    unsafe { DeviceIoControl(h.0, FSCTL_SET_COMPRESSION, &state as *const u16 as *const c_void, 2, null_mut(), 0, &mut ret, null_mut()) != 0 }
}

const TOKEN_ADJUST_PRIVILEGES: u32 = 0x20;
const SE_PRIVILEGE_ENABLED: u32 = 2;

/// Enable the privilege in process token.
pub fn set_privilege(name: &str) -> bool {
    let w = wide(name);
    // SAFETY: all pointers refer to local variables valid during calls,
    // token handle is closed by Handle.
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token) == 0 {
            return false;
        }
        let token = Handle(token);
        let mut tp = TOKEN_PRIVILEGES { count: 1, luid: LUID::default(), attributes: SE_PRIVILEGE_ENABLED };
        LookupPrivilegeValueW(null(), w.as_ptr(), &mut tp.luid) != 0
            && AdjustTokenPrivileges(token.0, 0, &tp, 0, null_mut(), null_mut()) != 0
            && GetLastError() == 0
    }
}

/// Check if the current user is a member of Administrators group.
pub fn is_user_admin() -> bool {
    const NT_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 5];
    const SECURITY_BUILTIN_DOMAIN_RID: u32 = 32;
    const DOMAIN_ALIAS_RID_ADMINS: u32 = 544;
    // SAFETY: sid is allocated by the system and freed by FreeSid.
    unsafe {
        let mut sid: *mut c_void = null_mut();
        if AllocateAndInitializeSid(&NT_AUTHORITY, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &mut sid) == 0 {
            return false;
        }
        let mut member: BOOL = 0;
        if CheckTokenMembership(null_mut(), sid, &mut member) == 0 {
            member = 0;
        }
        FreeSid(sid);
        member != 0
    }
}

pub const OWNER_SECURITY_INFORMATION: u32 = 1;
pub const GROUP_SECURITY_INFORMATION: u32 = 2;
pub const DACL_SECURITY_INFORMATION: u32 = 4;
pub const SACL_SECURITY_INFORMATION: u32 = 8;

/// Set self-relative security descriptor for file. The descriptor must be
/// checked with `winsys::valid_relative_sd` before.
pub fn set_file_security(name: &str, si: u32, sd: &[u8]) -> Result<(), u32> {
    // Copy to 4 byte aligned memory required for descriptor structures.
    let mut aligned = vec![0u32; sd.len().div_ceil(4)];
    for (i, c) in sd.chunks(4).enumerate() {
        let mut b = [0u8; 4];
        b[..c.len()].copy_from_slice(c);
        aligned[i] = u32::from_ne_bytes(b);
    }
    let w = wide_name(name);
    // SAFETY: w is zero terminated, aligned holds the descriptor data
    // and lives during the call.
    if unsafe { SetFileSecurityW(w.as_ptr(), si, aligned.as_ptr() as *const c_void) } != 0 {
        Ok(())
    } else {
        Err(last_error())
    }
}

/// Write reparse point data to an existing empty file or directory.
pub fn set_reparse_point(name: &str, data: &[u8]) -> Result<(), u32> {
    let h = open_existing(name, GENERIC_READ | GENERIC_WRITE, 0, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)?;
    let mut ret = 0u32;
    // SAFETY: input buffer is a valid slice of the declared size.
    let ok = unsafe { DeviceIoControl(h.0, FSCTL_SET_REPARSE_POINT, data.as_ptr() as *const c_void, data.len() as u32, null_mut(), 0, &mut ret, null_mut()) };
    if ok != 0 {
        Ok(())
    } else {
        Err(last_error())
    }
}

// Code pages.

pub const CP_ACP: u32 = 0;
pub const CP_OEMCP: u32 = 1;

pub fn ansi_cp() -> u32 {
    // SAFETY: no arguments.
    unsafe { GetACP() }
}

pub fn oem_cp() -> u32 {
    // SAFETY: no arguments.
    unsafe { GetOEMCP() }
}

/// Convert bytes in code page to string.
pub fn mb_to_wide(cp: u32, src: &[u8]) -> String {
    if src.is_empty() {
        return String::new();
    }
    let len = src.len().min(i32::MAX as usize / 2) as i32;
    let mut out = vec![0u16; len as usize];
    // SAFETY: buffers are valid for the passed sizes.
    let n = unsafe { MultiByteToWideChar(cp, 0, src.as_ptr(), len, out.as_mut_ptr(), len) };
    out.truncate(n.max(0) as usize);
    String::from_utf16_lossy(&out)
}

/// Convert string to code page, unmapped characters are replaced by
/// the default character.
pub fn wide_to_mb(cp: u32, s: &str) -> Vec<u8> {
    let w: Vec<u16> = s.encode_utf16().collect();
    if w.is_empty() {
        return Vec::new();
    }
    let len = w.len().min(i32::MAX as usize / 4) as i32;
    let mut out = vec![0u8; len as usize * 4];
    // SAFETY: buffers are valid for the passed sizes.
    let n = unsafe { WideCharToMultiByte(cp, 0, w.as_ptr(), len, out.as_mut_ptr(), out.len() as i32, null(), null_mut()) };
    out.truncate(n.max(0) as usize);
    out
}

// Time.

const UNIX_EPOCH_FT: i64 = 116444736000000000;

fn to_ft(t: i64) -> Option<FILETIME> {
    let v = t.checked_mul(10_000_000)?.checked_add(UNIX_EPOCH_FT)?;
    if v < 0 {
        return None;
    }
    Some(FILETIME { low: v as u32, high: (v >> 32) as u32 })
}

fn from_ft(ft: FILETIME) -> i64 {
    (((ft.high as i64) << 32 | ft.low as i64) - UNIX_EPOCH_FT).div_euclid(10_000_000)
}

/// Local time zone offset in seconds for Unix time, using the system
/// time zone rules for the year of this time.
pub fn local_offset(t: i64) -> Option<i64> {
    let ft = to_ft(t)?;
    let mut st = SYSTEMTIME::default();
    let mut lt = SYSTEMTIME::default();
    let mut lft = FILETIME::default();
    // SAFETY: all pointers refer to local variables.
    unsafe {
        if FileTimeToSystemTime(&ft, &mut st) == 0
            || SystemTimeToTzSpecificLocalTime(null(), &st, &mut lt) == 0
            || SystemTimeToFileTime(&lt, &mut lft) == 0
        {
            return None;
        }
    }
    Some(from_ft(lft) - t)
}

/// Convert local calendar time to Unix time.
pub fn local_to_unix(y: i64, mo: u32, d: u32, h: i64, mi: i64, s: i64) -> Option<i64> {
    let lt = SYSTEMTIME {
        year: u16::try_from(y).ok()?,
        month: mo as u16,
        day_of_week: 0,
        day: d as u16,
        hour: u16::try_from(h).ok()?,
        minute: u16::try_from(mi).ok()?,
        second: u16::try_from(s).ok()?,
        milliseconds: 0,
    };
    let mut st = SYSTEMTIME::default();
    let mut ft = FILETIME::default();
    // SAFETY: all pointers refer to local variables.
    unsafe {
        if TzSpecificLocalTimeToSystemTime(null(), &lt, &mut st) == 0 || SystemTimeToFileTime(&st, &mut ft) == 0 {
            return None;
        }
    }
    Some(from_ft(ft))
}

// Process.

const IDLE_PRIORITY_CLASS: u32 = 0x40;
const BELOW_NORMAL_PRIORITY_CLASS: u32 = 0x4000;
const NORMAL_PRIORITY_CLASS: u32 = 0x20;
const ABOVE_NORMAL_PRIORITY_CLASS: u32 = 0x8000;
const HIGH_PRIORITY_CLASS: u32 = 0x80;
const THREAD_PRIORITY_IDLE: i32 = -15;
const THREAD_PRIORITY_NORMAL: i32 = 0;
const THREAD_PRIORITY_ABOVE_NORMAL: i32 = 1;

/// Process and thread priority for -ri switch, 1 to 15.
pub fn set_priority(priority: i32) -> Option<i32> {
    let (class, level) = match priority {
        1 => (IDLE_PRIORITY_CLASS, THREAD_PRIORITY_IDLE),
        2..=6 => (IDLE_PRIORITY_CLASS, priority - 4),
        7 => (BELOW_NORMAL_PRIORITY_CLASS, THREAD_PRIORITY_ABOVE_NORMAL),
        8 | 9 => (NORMAL_PRIORITY_CLASS, priority - 7),
        10 => (ABOVE_NORMAL_PRIORITY_CLASS, THREAD_PRIORITY_NORMAL),
        11..=15 => (HIGH_PRIORITY_CLASS, priority - 13),
        _ => return None,
    };
    // SAFETY: pseudo handles of current process and thread.
    unsafe {
        SetPriorityClass(GetCurrentProcess(), class);
        SetThreadPriority(GetCurrentThread(), level);
    }
    Some(level)
}

/// Set priority level of the current thread, used for worker threads.
pub fn set_thread_priority(level: i32) {
    // SAFETY: pseudo handle of current thread.
    unsafe {
        SetThreadPriority(GetCurrentThread(), level);
    }
}

/// Prevent the system from going to sleep while working.
pub fn keep_system_awake() {
    const ES_SYSTEM_REQUIRED: u32 = 1;
    // SAFETY: no pointers passed.
    unsafe {
        SetThreadExecutionState(ES_SYSTEM_REQUIRED);
    }
}

/// Named event signaling that some copy waits to turn off the computer.
/// Returns the event handle and true if it already existed.
pub struct NamedEvent(#[allow(dead_code)] Handle); // Closed on drop.

pub fn create_event(name: &str) -> Option<(NamedEvent, bool)> {
    const ERROR_ALREADY_EXISTS: u32 = 183;
    let w = wide(name);
    // SAFETY: w is a zero terminated string valid during the call.
    let h = unsafe { CreateEventW(null(), 0, 0, w.as_ptr()) };
    if h.is_null() {
        return None;
    }
    let existed = last_error() == ERROR_ALREADY_EXISTS;
    Some((NamedEvent(Handle(h)), existed))
}

pub fn exit_windows(restart: bool) {
    const EWX_SHUTDOWN: u32 = 1;
    const EWX_REBOOT: u32 = 2;
    const EWX_FORCE: u32 = 4;
    const SHTDN_REASON_FLAG_PLANNED: u32 = 0x80000000;
    // SAFETY: no pointers passed.
    unsafe {
        ExitWindowsEx(if restart { EWX_REBOOT } else { EWX_SHUTDOWN } | EWX_FORCE, SHTDN_REASON_FLAG_PLANNED);
    }
}

pub fn suspend(hibernate: bool) {
    // SAFETY: no pointers passed.
    unsafe {
        SetSuspendState(hibernate as u8, 0, 0);
    }
}
