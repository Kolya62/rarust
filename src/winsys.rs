// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Windows specific services: junctions and symbolic links, security
//! descriptors, file attributes, NTFS compression, console password input,
//! process priority and power off. Outside of Windows these functions do
//! nothing, callers check `cfg!(windows)` before using them.

#[cfg(windows)]
use crate::errhnd::*;
#[cfg(windows)]
use crate::ui::{ui_msg, UiMsg};

pub const FILE_ATTRIBUTE_COMPRESSED: u32 = 0x800;

#[cfg(windows)]
use crate::win32;

#[cfg(windows)]
fn report_os_error(code: u32) {
    set_os_error(&win32::os_error(code));
    sys_err_msg();
}

/// Show "run as administrator" hint if access was denied.
#[cfg(windows)]
fn need_admin_hint(code: u32) {
    if (code == win32::ERROR_ACCESS_DENIED || code == win32::ERROR_PRIVILEGE_NOT_HELD) && !win32::is_user_admin() {
        ui_msg(UiMsg::NeedAdmin);
    }
}

/// Set all file attributes.
pub fn set_file_attr(name: &str, attr: u32) -> bool {
    #[cfg(windows)]
    match win32::set_file_attr(name, attr) {
        Ok(()) => true,
        Err(e) => {
            set_os_error(&win32::os_error(e));
            false
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (name, attr);
        false
    }
}

/// Set NTFS compression for file or directory.
pub fn set_compression(name: &str) -> bool {
    #[cfg(windows)]
    return win32::set_compression(name);
    #[cfg(not(windows))]
    {
        let _ = name;
        false
    }
}

/// Reparse point data for junction or symbolic link.
fn reparse_data(junction: bool, subst: &str, print: &str, relative: bool) -> Vec<u8> {
    const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA0000003;
    const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000000C;
    const SYMLINK_FLAG_RELATIVE: u32 = 1;
    let s: Vec<u16> = subst.encode_utf16().collect();
    let p: Vec<u16> = print.encode_utf16().collect();
    let mut path = Vec::new();
    for c in s.iter().chain([0u16].iter()).chain(p.iter()).chain([0u16].iter()) {
        path.extend_from_slice(&c.to_le_bytes());
    }
    let w16 = |v: &mut Vec<u8>, x: usize| v.extend_from_slice(&(x as u16).to_le_bytes());
    let mut hdr = Vec::new();
    w16(&mut hdr, 0); // Substitute name offset.
    w16(&mut hdr, s.len() * 2);
    w16(&mut hdr, (s.len() + 1) * 2); // Print name offset.
    w16(&mut hdr, p.len() * 2);
    if !junction {
        hdr.extend_from_slice(&(if relative { SYMLINK_FLAG_RELATIVE } else { 0 }).to_le_bytes());
    }
    let tag = if junction { IO_REPARSE_TAG_MOUNT_POINT } else { IO_REPARSE_TAG_SYMLINK };
    let mut d = Vec::new();
    d.extend_from_slice(&tag.to_le_bytes());
    w16(&mut d, hdr.len() + path.len()); // Reparse data length.
    w16(&mut d, 0); // Reserved.
    d.extend_from_slice(&hdr);
    d.extend_from_slice(&path);
    d
}

/// Turn an existing empty file or directory `name` into junction or
/// symbolic link. Reports errors and removes `name` on failure.
pub fn create_reparse_point(name: &str, junction: bool, subst: &str, print: &str, abs_path: bool, is_dir: bool) -> bool {
    let data = reparse_data(junction, subst, print, !abs_path);
    #[cfg(windows)]
    {
        use std::sync::Once;
        static PRIV: Once = Once::new();
        PRIV.call_once(|| {
            win32::set_privilege("SeRestorePrivilege");
            win32::set_privilege("SeCreateSymbolicLinkPrivilege");
        });
        match win32::set_reparse_point(name, &data) {
            Ok(()) => true,
            Err(e) => {
                ui_msg(UiMsg::SLinkCreate(String::new(), name.to_string()));
                need_admin_hint(e);
                report_os_error(e);
                set_error_code(RARX_CREATE);
                if is_dir {
                    let _ = std::fs::remove_dir(name);
                } else {
                    let _ = std::fs::remove_file(name);
                }
                false
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (name, data, is_dir);
        false
    }
}

/// Check that self-relative security descriptor and all its parts are
/// inside of the buffer, so the system never reads past archive data.
pub fn valid_relative_sd(sd: &[u8]) -> bool {
    const SE_DACL_PRESENT: u16 = 0x4;
    const SE_SACL_PRESENT: u16 = 0x10;
    const SE_SELF_RELATIVE: u16 = 0x8000;
    let u16at = |p: usize| sd.get(p..p + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let u32at = |p: usize| sd.get(p..p + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize);
    let valid_sid = |p: usize| -> bool {
        // Revision 1, up to 15 subauthorities, 8 + 4 * count bytes.
        match (sd.get(p), sd.get(p + 1)) {
            (Some(1), Some(&n)) if n <= 15 => p + 8 + 4 * n as usize <= sd.len(),
            _ => false,
        }
    };
    let valid_acl = |p: usize| -> bool {
        let (Some(&rev), Some(size), Some(count)) = (sd.get(p), u16at(p + 2), u16at(p + 4)) else {
            return false;
        };
        let size = size as usize;
        if !(2..=4).contains(&rev) || size < 8 || p + size > sd.len() {
            return false;
        }
        let mut ace = p + 8;
        for _ in 0..count {
            match u16at(ace + 2) {
                Some(ace_size) if ace_size >= 4 && ace + ace_size as usize <= p + size => ace += ace_size as usize,
                _ => return false,
            }
        }
        true
    };
    let (Some(1), Some(control)) = (sd.first().copied(), u16at(2)) else {
        return false;
    };
    if control & SE_SELF_RELATIVE == 0 {
        return false;
    }
    let (Some(owner), Some(group), Some(sacl), Some(dacl)) = (u32at(4), u32at(8), u32at(12), u32at(16)) else {
        return false;
    };
    (owner == 0 || valid_sid(owner))
        && (group == 0 || valid_sid(group))
        && (control & SE_SACL_PRESENT == 0 || sacl == 0 || valid_acl(sacl))
        && (control & SE_DACL_PRESENT == 0 || dacl == 0 || valid_acl(dacl))
}

/// Set security descriptor of extracted file. Owner, group, DACL and,
/// if privilege is available, SACL are set.
pub fn set_acl(arc_name: &str, file_name: &str, sd: &[u8]) {
    #[cfg(windows)]
    {
        use std::sync::OnceLock;
        static READ_SACL: OnceLock<bool> = OnceLock::new();
        let read_sacl = *READ_SACL.get_or_init(|| {
            let sacl = win32::set_privilege("SeSecurityPrivilege");
            win32::set_privilege("SeRestorePrivilege");
            sacl
        });
        let mut si = win32::OWNER_SECURITY_INFORMATION | win32::GROUP_SECURITY_INFORMATION | win32::DACL_SECURITY_INFORMATION;
        if read_sacl {
            si |= win32::SACL_SECURITY_INFORMATION;
        }
        const ERROR_INVALID_SECURITY_DESCR: u32 = 1338;
        let r = if valid_relative_sd(sd) { win32::set_file_security(file_name, si, sd) } else { Err(ERROR_INVALID_SECURITY_DESCR) };
        if let Err(e) = r {
            ui_msg(UiMsg::AclSet(arc_name.to_string(), file_name.to_string()));
            report_os_error(e);
            if e == win32::ERROR_ACCESS_DENIED && !win32::is_user_admin() {
                ui_msg(UiMsg::NeedAdmin);
            }
            set_error_code(RARX_WARNING);
        }
    }
    #[cfg(not(windows))]
    let _ = (arc_name, file_name, sd);
}

/// Enable or disable console echo for password input. Returns false if
/// input is not a console.
pub fn set_console_echo(on: bool) -> bool {
    #[cfg(windows)]
    return win32::set_console_echo(on);
    #[cfg(not(windows))]
    {
        let _ = on;
        false
    }
}

thread_local! {
    static SLEEP_TIME: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    static LAST_SLEEP: std::cell::Cell<Option<std::time::Instant>> = const { std::cell::Cell::new(None) };
}

/// Set process and thread priority and pause time for -ri switch.
pub fn set_priority(priority: i32, sleep_time: i32) {
    SLEEP_TIME.with(|s| s.set(sleep_time.max(0) as u32));
    #[cfg(windows)]
    if let Some(level) = win32::set_priority(priority) {
        WORKER_PRIORITY.store(level, std::sync::atomic::Ordering::Relaxed);
    }
    #[cfg(not(windows))]
    let _ = priority;
}

#[cfg(windows)]
static WORKER_PRIORITY: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// Apply -ri thread priority to a worker thread.
pub fn set_worker_thread_priority() {
    #[cfg(windows)]
    {
        let level = WORKER_PRIORITY.load(std::sync::atomic::Ordering::Relaxed);
        if level != 0 {
            win32::set_thread_priority(level);
        }
    }
}

/// Pause between processing steps, so other tasks can use processor time.
pub fn wait() {
    let t = SLEEP_TIME.with(|s| s.get());
    if t == 0 {
        return;
    }
    let now = std::time::Instant::now();
    match LAST_SLEEP.with(|l| l.get()) {
        None => LAST_SLEEP.with(|l| l.set(Some(now))),
        Some(last) if now.duration_since(last).as_millis() > 10 => {
            std::thread::sleep(std::time::Duration::from_millis(t as u64));
            LAST_SLEEP.with(|l| l.set(Some(std::time::Instant::now())));
        }
        _ => {}
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum PowerMode {
    #[default]
    Keep,
    Off,
    Hibernate,
    Sleep,
    Restart,
}

/// Named event existing while some copy waits to turn off the computer.
#[cfg(windows)]
const SHUTDOWN_EVENT: &str = "rar -ioff";

#[cfg(windows)]
thread_local! {
    static SHUTDOWN_HANDLE: std::cell::RefCell<Option<win32::NamedEvent>> = const { std::cell::RefCell::new(None) };
}

/// Register this copy as waiting to turn off the computer.
pub fn shutdown_register() {
    #[cfg(windows)]
    if let Some((h, _)) = win32::create_event(SHUTDOWN_EVENT) {
        SHUTDOWN_HANDLE.with(|s| *s.borrow_mut() = Some(h));
    }
}

/// Check if other copies started with -ioff are still running.
#[cfg(windows)]
fn other_shutdown_pending() -> bool {
    // Close our event and check if other copies still own it.
    SHUTDOWN_HANDLE.with(|s| s.borrow_mut().take());
    matches!(win32::create_event(SHUTDOWN_EVENT), Some((_, true)))
}

/// Turn off, restart, hibernate or put the computer to sleep for -ioff.
pub fn shutdown(mode: PowerMode) {
    #[cfg(windows)]
    if mode != PowerMode::Keep && !other_shutdown_pending() {
        win32::set_privilege("SeShutdownPrivilege");
        match mode {
            PowerMode::Off => win32::exit_windows(false),
            PowerMode::Restart => win32::exit_windows(true),
            PowerMode::Sleep => win32::suspend(false),
            PowerMode::Hibernate => win32::suspend(true),
            PowerMode::Keep => {}
        }
    }
    #[cfg(not(windows))]
    let _ = mode;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_descriptor_check() {
        // Owner and group S-1-5-32-544, DACL with one ACE for Everyone.
        let sid = [1u8, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0];
        let everyone = [1u8, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        let mut ace = vec![0u8, 0, 20, 0, 0xff, 0x01, 0x1f, 0];
        ace.extend_from_slice(&everyone);
        let mut acl = vec![2u8, 0, 28, 0, 1, 0, 0, 0];
        acl.extend_from_slice(&ace);
        let mut sd = vec![1u8, 0, 0x04, 0x80, 20, 0, 0, 0, 36, 0, 0, 0, 0, 0, 0, 0, 52, 0, 0, 0];
        sd.extend_from_slice(&sid);
        sd.extend_from_slice(&sid);
        sd.extend_from_slice(&acl);
        assert!(valid_relative_sd(&sd));
        assert!(!valid_relative_sd(&sd[..sd.len() - 1]));
        let mut bad = sd.clone();
        bad[4] = 200; // Owner outside of buffer.
        assert!(!valid_relative_sd(&bad));
        let mut bad = sd.clone();
        bad[54] = 200; // ACL size larger than buffer.
        assert!(!valid_relative_sd(&bad));
        let mut bad = sd.clone();
        bad[62] = 100; // ACE size larger than ACL.
        assert!(!valid_relative_sd(&bad));
        let mut bad = sd.clone();
        bad[3] = 0; // Absolute descriptor.
        assert!(!valid_relative_sd(&bad));
    }

    #[test]
    fn reparse_buffer() {
        let d = reparse_data(true, "\\??\\C:\\a", "C:\\a", false);
        assert_eq!(&d[0..4], &0xA0000003u32.to_le_bytes());
        // 8 bytes of offsets and lengths, 9 + 5 characters with zeroes.
        assert_eq!(u16::from_le_bytes([d[4], d[5]]) as usize, 8 + (9 + 5) * 2);
        assert_eq!(d.len(), 8 + 8 + (9 + 5) * 2);
        let d = reparse_data(false, "..\\t", "..\\t", true);
        assert_eq!(&d[0..4], &0xA000000Cu32.to_le_bytes());
        assert_eq!(&d[16..20], &1u32.to_le_bytes());
        assert_eq!(d.len(), 8 + 12 + 10 * 2);
    }
}
