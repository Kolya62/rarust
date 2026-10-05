// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! File search.

use crate::matchfn::{cmp_name, MATCH_NAMES};
use crate::pathfn::{get_name_pos, point_to_name, remove_name_from_path};
use crate::timefn::RarTime;
use crate::unicode::{from_os, to_path};

#[derive(Clone, Debug, Default)]
pub struct FindData {
    pub name: String,
    pub size: u64,
    pub file_attr: u32,
    pub is_dir: bool,
    pub is_link: bool,
    pub mtime: RarTime,
    pub ctime: RarTime,
    pub atime: RarTime,
    pub flags: u32,
    pub error: bool,
}

pub fn metadata_attr(m: &std::fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        m.mode()
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        m.file_attributes()
    }
    #[cfg(not(any(unix, windows)))]
    {
        let mut a = if m.is_dir() { 0x10 } else { 0x20 };
        if m.permissions().readonly() {
            a |= 1;
        }
        if m.file_type().is_symlink() {
            a |= 0x400;
        }
        a
    }
}

fn fill_times(m: &std::fs::Metadata, fd: &mut FindData) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        fd.mtime.set_unix_ns((m.mtime() as u64).wrapping_mul(1_000_000_000).wrapping_add(m.mtime_nsec() as u64));
        fd.ctime.set_unix_ns((m.ctime() as u64).wrapping_mul(1_000_000_000).wrapping_add(m.ctime_nsec() as u64));
        fd.atime.set_unix_ns((m.atime() as u64).wrapping_mul(1_000_000_000).wrapping_add(m.atime_nsec() as u64));
    }
    #[cfg(not(unix))]
    {
        if let Ok(t) = m.modified() {
            fd.mtime = RarTime::from_system_time(t);
        }
        if let Ok(t) = m.created() {
            fd.ctime = RarTime::from_system_time(t);
        }
        if let Ok(t) = m.accessed() {
            fd.atime = RarTime::from_system_time(t);
        }
    }
}

/// Get information about a single file without wildcards.
pub fn fast_find(name: &str, fd: &mut FindData, get_sym_link: bool) -> bool {
    fd.error = false;
    let p = to_path(name);
    let m = if get_sym_link { std::fs::symlink_metadata(&p) } else { std::fs::metadata(&p) };
    match m {
        Ok(m) => {
            fd.file_attr = metadata_attr(&m);
            fd.size = m.len();
            fill_times(&m, fd);
            fd.name = name.to_string();
            fd.flags = 0;
            fd.is_dir = crate::filefn::is_dir(fd.file_attr);
            fd.is_link = crate::filefn::is_link(fd.file_attr) || m.file_type().is_symlink();
            true
        }
        Err(e) => {
            fd.error = e.kind() != std::io::ErrorKind::NotFound;
            false
        }
    }
}

#[derive(Default)]
pub struct FindFile {
    mask: String,
    entries: Option<std::fs::ReadDir>,
    first_call: bool,
}

impl FindFile {
    pub fn new() -> FindFile {
        FindFile { mask: String::new(), entries: None, first_call: true }
    }

    pub fn set_mask(&mut self, mask: &str) {
        self.mask = mask.to_string();
        self.first_call = true;
        self.entries = None;
    }

    pub fn next(&mut self, fd: &mut FindData, get_sym_link: bool) -> bool {
        fd.error = false;
        if self.mask.is_empty() {
            return false;
        }
        if self.first_call {
            let mut dir = self.mask.clone();
            remove_name_from_path(&mut dir);
            if dir.is_empty() {
                dir = ".".to_string();
            }
            match std::fs::read_dir(to_path(&dir)) {
                Ok(r) => self.entries = Some(r),
                Err(e) => {
                    fd.error = e.kind() != std::io::ErrorKind::NotFound;
                    return false;
                }
            }
        }
        loop {
            let ent = match self.entries.as_mut().and_then(|e| e.next()) {
                Some(Ok(e)) => e,
                Some(Err(_)) => continue,
                None => return false,
            };
            let name = from_os(&ent.file_name());
            if name == "." || name == ".." {
                continue;
            }
            if cmp_name(&self.mask, &name, MATCH_NAMES) {
                let mut full = self.mask[..get_name_pos(&self.mask)].to_string();
                full.push_str(&name);
                if !fast_find(&full, fd, get_sym_link) {
                    crate::errhnd::open_error_msg("", &full);
                    continue;
                }
                fd.name = full;
                break;
            }
        }
        fd.flags = 0;
        self.first_call = false;
        let n = point_to_name(&fd.name);
        if n == "." || n == ".." {
            return self.next(fd, get_sym_link);
        }
        true
    }
}
