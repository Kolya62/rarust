// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! File system helpers.

use crate::find::{fast_find, FindData};
use crate::loclang::*;
use crate::pathfn::{chars, get_last_char, is_path_div, is_wildcard};
use crate::timefn::RarTime;
use crate::unicode::to_path;
use crate::wfmt;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MkdirCode {
    Success,
    Error,
    BadPath,
}

pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;

pub fn make_dir(name: &str, set_attr: bool, attr: u32) -> MkdirCode {
    #[allow(unused_mut)]
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(if set_attr { attr } else { 0o777 });
    }
    #[cfg(not(unix))]
    let _ = (set_attr, attr);
    match b.create(to_path(name)) {
        Ok(()) => {
            if cfg!(windows) && set_attr {
                set_file_attr(name, attr);
            }
            MkdirCode::Success
        }
        Err(e) => {
            crate::errhnd::set_os_error(&e);
            if e.kind() == std::io::ErrorKind::NotFound {
                MkdirCode::BadPath
            } else {
                MkdirCode::Error
            }
        }
    }
}

pub fn create_dir(name: &str) -> bool {
    make_dir(name, false, 0) == MkdirCode::Success
}

pub fn create_path(path: &str, skip_last_name: bool, silent: bool) -> bool {
    if path.is_empty() {
        return false;
    }
    let v = chars(path);
    let dir_attr = if cfg!(unix) { 0o777 } else { 0 };
    let mut success = true;
    for i in 1..v.len() {
        if is_path_div(v[i]) {
            if !cfg!(unix) && i == 2 && v[1] == ':' {
                continue;
            }
            let dir: String = v[..i].iter().collect();
            success = make_dir(&dir, true, dir_attr) == MkdirCode::Success;
            if success && !silent {
                crate::consio::mprintf(&wfmt!(MCreatDir, dir));
                crate::consio::mprintf(&wfmt!(" %s", MOk));
            }
        }
    }
    if !skip_last_name && !is_path_div(get_last_char(path)) {
        success = make_dir(path, true, dir_attr) == MkdirCode::Success;
    }
    success
}

pub fn set_dir_time(name: &str, ftm: Option<&RarTime>, ftc: Option<&RarTime>, fta: Option<&RarTime>) {
    crate::file::set_file_times_by_name(name, ftm, ftc, fta);
}

pub fn is_removable(_name: &str) -> bool {
    false
}

pub fn file_exist(name: &str) -> bool {
    std::fs::symlink_metadata(to_path(name)).is_ok() || std::fs::metadata(to_path(name)).is_ok()
}

pub fn wild_file_exist(name: &str) -> bool {
    if is_wildcard(name) {
        let mut f = crate::find::FindFile::new();
        f.set_mask(name);
        let mut fd = FindData::default();
        return f.next(&mut fd, false);
    }
    file_exist(name)
}

pub fn is_dir(attr: u32) -> bool {
    if cfg!(unix) {
        (attr & 0xF000) == 0x4000
    } else {
        attr != 0xffffffff && (attr & FILE_ATTRIBUTE_DIRECTORY) != 0
    }
}

pub fn is_link(attr: u32) -> bool {
    if cfg!(unix) {
        (attr & 0xF000) == 0xA000
    } else {
        attr != 0xffffffff && (attr & 0x400) != 0
    }
}

/// Get file attributes (Unix mode). Returns 0 if file does not exist.
pub fn get_file_attr(name: &str) -> u32 {
    match std::fs::metadata(to_path(name)) {
        Ok(m) => crate::find::metadata_attr(&m),
        Err(_) => {
            if cfg!(unix) {
                0
            } else {
                0xffffffff
            }
        }
    }
}

pub fn set_file_attr(name: &str, attr: u32) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::set_permissions(to_path(name), std::fs::Permissions::from_mode(attr & 0o7777)) {
            Ok(()) => true,
            Err(e) => {
                crate::errhnd::set_os_error(&e);
                false
            }
        }
    }
    #[cfg(windows)]
    return crate::winsys::set_file_attr(name, attr);
    #[cfg(not(any(unix, windows)))]
    {
        let p = to_path(name);
        match std::fs::metadata(&p) {
            Ok(m) => {
                let mut perm = m.permissions();
                perm.set_readonly(attr & 1 != 0);
                std::fs::set_permissions(&p, perm).is_ok()
            }
            Err(_) => false,
        }
    }
}

pub fn prepare_to_delete(name: &str) {
    if cfg!(unix) {
        set_file_attr(name, 0o700);
    } else {
        set_file_attr(name, 0);
    }
}

pub fn del_file(name: &str) -> bool {
    match std::fs::remove_file(to_path(name)) {
        Ok(()) => true,
        Err(e) => {
            crate::errhnd::set_os_error(&e);
            false
        }
    }
}

pub fn del_dir(name: &str) -> bool {
    std::fs::remove_dir(to_path(name)).is_ok()
}

pub fn rename_file(src: &str, dest: &str) -> bool {
    std::fs::rename(to_path(src), to_path(dest)).is_ok()
}

pub fn mk_temp(name: &mut String, ext: Option<&str>) -> bool {
    let mut t = RarTime::default();
    t.set_current_time();
    let random = (t.get_win() / 100000) as u32;
    let pid = std::process::id();
    let ext = ext.unwrap_or(".rartemp");
    for attempt in 0..1000u32 {
        let random_ext = random % 50000 + attempt;
        let new_name = format!("{}{}.{}{}", name, pid, random_ext, ext);
        if !file_exist(&new_name) {
            *name = new_name;
            return true;
        }
    }
    false
}

/// Delete symlinks to directories in path, so files are not extracted
/// via such links.
pub fn links_to_dirs(src_name: &str, skip_part: &str, last_checked: &mut String) -> bool {
    let path_v = chars(src_name);
    let last = chars(last_checked);
    let mut skip_len = chars(skip_part).len();
    if skip_len > 0 && !src_name.starts_with(skip_part) {
        skip_len = 0;
    }
    let mut i = 0;
    while i < path_v.len() && i < last.len() && path_v[i] == last[i] {
        if is_path_div(path_v[i]) && i > skip_len {
            skip_len = i;
        }
        i += 1;
    }
    while skip_len < path_v.len() && is_path_div(path_v[skip_len]) {
        skip_len += 1;
    }
    if !path_v.is_empty() {
        let mut i = path_v.len() - 1;
        while i > skip_len {
            if is_path_div(path_v[i]) {
                let p: String = path_v[..i].iter().collect();
                let mut fd = FindData::default();
                if fast_find(&p, &mut fd, true) && fd.is_link && !del_dir(&p) && !del_file(&p) {
                    crate::errhnd::create_error_msg("", src_name);
                    return false;
                }
            }
            i -= 1;
        }
    }
    *last_checked = src_name.to_string();
    true
}
