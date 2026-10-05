// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! File wrapper used by archive processing.

use crate::errhnd;
use crate::timefn::RarTime;
use crate::unicode::to_path;
use std::io::{Read, Seek, SeekFrom, Write};

pub const FMF_READ: u32 = 0;
pub const FMF_UPDATE: u32 = 1;
pub const FMF_WRITE: u32 = 2;
pub const FMF_OPENSHARED: u32 = 4;
pub const FMF_OPENEXCLUSIVE: u32 = 8;
pub const FMF_SHAREREAD: u32 = 16;
pub const FMF_STANDARDNAMES: u32 = 32;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum FileErrorType {
    #[default]
    Success,
    NotFound,
    ReadError,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ReadErrorMode {
    #[default]
    Ask,
    Truncate,
    Ignore,
}

#[derive(Debug, Default)]
enum Handle {
    #[default]
    None,
    Disk(std::fs::File),
    Std,
}

#[derive(Debug, Default)]
pub struct File {
    h: Handle,
    std_type: bool,
    new_file: bool,
    line_input: bool,
    read_error_mode: ReadErrorMode,
    truncated_after_read_error: bool,
    cur_file_pos: i64,
    allow_delete_off: bool,
    no_exceptions: bool,
    pub open_shared: bool,
    /// Windows file attributes applied when creating a file.
    pub create_attr: u32,
    pub file_name: String,
    pub error_type: FileErrorType,
}

impl Drop for File {
    fn drop(&mut self) {
        if self.is_opened() {
            if self.new_file {
                self.delete();
            } else {
                self.close();
            }
        }
    }
}

pub const SEEK_SET: i32 = 0;
pub const SEEK_CUR: i32 = 1;
pub const SEEK_END: i32 = 2;

impl File {
    pub fn new() -> File {
        File::default()
    }

    pub fn open(&mut self, name: &str, mode: u32) -> bool {
        self.error_type = FileErrorType::Success;
        let update = mode & FMF_UPDATE != 0;
        let write = mode & FMF_WRITE != 0;
        let mut o = std::fs::OpenOptions::new();
        if update {
            o.read(true).write(true);
        } else if write {
            o.write(true);
        } else {
            o.read(true);
        }
        let r = o.open(to_path(name));
        self.new_file = false;
        self.std_type = false;
        match r {
            Ok(f) => {
                if self.is_opened() {
                    self.close();
                }
                self.h = Handle::Disk(f);
                self.file_name = name.to_string();
                self.truncated_after_read_error = false;
                self.cur_file_pos = 0;
                true
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    self.error_type = FileErrorType::NotFound;
                }
                errhnd::set_os_error(&e);
                false
            }
        }
    }

    pub fn t_open(&mut self, name: &str) {
        if !self.w_open(name) {
            errhnd::exit(errhnd::RARX_OPEN);
        }
    }

    pub fn w_open(&mut self, name: &str) -> bool {
        if self.open(name, FMF_READ) {
            return true;
        }
        errhnd::open_error_msg("", name);
        false
    }

    pub fn create(&mut self, name: &str, mode: u32) -> bool {
        let write = mode & FMF_WRITE != 0;
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        if !write {
            o.read(true);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            if self.create_attr != 0 {
                o.attributes(self.create_attr);
            }
        }
        if self.is_opened() {
            self.close();
        }
        let r = o.open(to_path(name));
        self.new_file = true;
        self.std_type = false;
        self.file_name = name.to_string();
        match r {
            Ok(f) => {
                self.h = Handle::Disk(f);
                true
            }
            Err(e) => {
                errhnd::set_os_error(&e);
                self.h = Handle::None;
                false
            }
        }
    }

    pub fn w_create(&mut self, name: &str, mode: u32) -> bool {
        if self.create(name, mode) {
            return true;
        }
        errhnd::create_error_msg("", name);
        false
    }

    pub fn close(&mut self) -> bool {
        let success = true;
        self.h = Handle::None;
        self.std_type = false;
        self.new_file = false;
        success
    }

    pub fn delete(&mut self) -> bool {
        if self.std_type {
            return false;
        }
        if self.is_opened() {
            self.close();
        }
        if self.allow_delete_off {
            return false;
        }
        crate::filefn::del_file(&self.file_name)
    }

    pub fn rename(&mut self, new_name: &str) -> bool {
        let ok = new_name == self.file_name || crate::filefn::rename_file(&self.file_name, new_name);
        if ok {
            self.file_name = new_name.to_string();
        }
        ok
    }

    pub fn set_handle_std(&mut self) {
        self.std_type = true;
        self.h = Handle::Std;
    }

    pub fn is_std(&self) -> bool {
        self.std_type
    }

    pub fn set_line_input_mode(&mut self, m: bool) {
        self.line_input = m;
    }

    pub fn is_opened(&self) -> bool {
        !matches!(self.h, Handle::None)
    }

    pub fn is_seekable(&self) -> bool {
        !self.std_type
    }

    pub fn set_allow_delete(&mut self, allow: bool) {
        self.allow_delete_off = !allow;
    }

    pub fn set_exceptions(&mut self, allow: bool) {
        self.no_exceptions = !allow;
    }

    pub fn set_read_error_mode(&mut self, m: ReadErrorMode) {
        self.read_error_mode = m;
    }

    pub fn is_truncated_after_read_error(&self) -> bool {
        self.truncated_after_read_error
    }

    /// Mark the file as already existing, so it is not deleted on drop.
    pub fn keep(&mut self) {
        self.new_file = false;
    }

    pub fn write(&mut self, data: &[u8]) -> bool {
        if data.is_empty() {
            return true;
        }
        loop {
            let r = match &mut self.h {
                Handle::Disk(f) => f.write_all(data),
                Handle::Std => {
                    let mut o = std::io::stdout().lock();
                    o.write_all(data).and_then(|_| o.flush())
                }
                Handle::None => Err(std::io::Error::other("file is not opened")),
            };
            match r {
                Ok(()) => return true,
                Err(e) => {
                    errhnd::set_os_error(&e);
                    if !self.no_exceptions && !self.std_type {
                        if errhnd::ask_repeat_write(&self.file_name, false) {
                            continue;
                        }
                        errhnd::write_error("", &self.file_name);
                    }
                    return false;
                }
            }
        }
    }

    fn direct_read(&mut self, buf: &mut [u8]) -> i32 {
        let r = match &mut self.h {
            Handle::Disk(f) => {
                let mut total = 0;
                loop {
                    match f.read(&mut buf[total..]) {
                        Ok(0) => break Ok(total),
                        Ok(n) => {
                            total += n;
                            if total == buf.len() {
                                break Ok(total);
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(e) => {
                            if total > 0 {
                                break Ok(total);
                            }
                            break Err(e);
                        }
                    }
                }
            }
            Handle::Std => std::io::stdin().lock().read(buf),
            Handle::None => Err(std::io::Error::other("file is not opened")),
        };
        match r {
            Ok(n) => n as i32,
            Err(e) => {
                errhnd::set_os_error(&e);
                -1
            }
        }
    }

    /// Read data. Returns number of bytes read, 0 at end of file.
    pub fn read(&mut self, buf: &mut [u8]) -> i32 {
        if self.truncated_after_read_error {
            return 0;
        }
        let file_pos = if self.read_error_mode == ReadErrorMode::Ignore { self.tell() } else { 0 };
        let mut total: i32 = 0;
        let mut off = 0usize;
        loop {
            let mut read_size = self.direct_read(&mut buf[off..]);
            if read_size == -1 {
                self.error_type = FileErrorType::ReadError;
                if !self.no_exceptions {
                    if self.read_error_mode == ReadErrorMode::Ignore {
                        read_size = 0;
                        let size = buf.len();
                        let mut i = 0;
                        while i < size {
                            self.seek(file_pos + i as i64, SEEK_SET);
                            let n = (size - i).min(512);
                            let code = self.direct_read(&mut buf[i..i + n]);
                            read_size += if code == -1 { 512 } else { code };
                            total += read_size;
                            i += 512;
                        }
                    } else {
                        let mut ignore = false;
                        if self.read_error_mode == ReadErrorMode::Ask && !self.std_type && self.is_opened() {
                            let (ig, retry, _quit) = errhnd::ask_repeat_read(&self.file_name);
                            ignore = ig;
                            if retry {
                                continue;
                            }
                        }
                        if ignore || self.read_error_mode == ReadErrorMode::Truncate {
                            self.truncated_after_read_error = true;
                            return 0;
                        }
                        errhnd::read_error(&self.file_name);
                    }
                }
            }
            total += read_size;
            if self.std_type && !self.line_input && read_size > 0 && (off + (read_size as usize)) < buf.len() {
                off += read_size as usize;
                continue;
            }
            break;
        }
        if total > 0 {
            self.cur_file_pos += total as i64;
        }
        total
    }

    pub fn seek(&mut self, offset: i64, method: i32) {
        if !self.raw_seek(offset, method) && !self.no_exceptions {
            errhnd::seek_error(&self.file_name);
        }
    }

    pub fn raw_seek(&mut self, offset: i64, method: i32) -> bool {
        if !self.is_opened() {
            return true;
        }
        if !self.is_seekable() {
            let mut buf = [0u8; 4096];
            if method == SEEK_CUR || method == SEEK_SET && offset >= self.cur_file_pos {
                let mut skip = if method == SEEK_CUR { offset } else { offset - self.cur_file_pos } as u64;
                while skip > 0 {
                    let n = (skip as usize).min(buf.len());
                    let r = self.read(&mut buf[..n]);
                    if r <= 0 {
                        return false;
                    }
                    skip -= r as u64;
                }
                return true;
            }
            if method == SEEK_END {
                while self.read(&mut buf) > 0 {}
                return true;
            }
            return false;
        }
        let (mut offset, mut method) = (offset, method);
        if offset < 0 && method != SEEK_SET {
            offset += if method == SEEK_CUR { self.tell() } else { self.file_length() };
            method = SEEK_SET;
        }
        let pos = match method {
            SEEK_SET => {
                if offset < 0 {
                    return false;
                }
                SeekFrom::Start(offset as u64)
            }
            SEEK_CUR => SeekFrom::Current(offset),
            _ => SeekFrom::End(offset),
        };
        match &mut self.h {
            Handle::Disk(f) => match f.seek(pos) {
                Ok(_) => true,
                Err(e) => {
                    errhnd::set_os_error(&e);
                    false
                }
            },
            _ => false,
        }
    }

    pub fn tell(&mut self) -> i64 {
        if !self.is_opened() {
            if !self.no_exceptions {
                errhnd::seek_error(&self.file_name);
            }
            return -1;
        }
        if !self.is_seekable() {
            return self.cur_file_pos;
        }
        match &mut self.h {
            Handle::Disk(f) => f.stream_position().map(|p| p as i64).unwrap_or(-1),
            _ => -1,
        }
    }

    pub fn file_length(&mut self) -> i64 {
        match &self.h {
            Handle::Disk(f) => f.metadata().map(|m| m.len() as i64).unwrap_or(0),
            _ => {
                let save = self.tell();
                self.seek(0, SEEK_END);
                let l = self.tell();
                self.seek(save, SEEK_SET);
                l
            }
        }
    }

    pub fn get_byte(&mut self) -> u8 {
        let mut b = [0u8; 1];
        self.read(&mut b);
        b[0]
    }

    pub fn truncate(&mut self) -> bool {
        let pos = self.tell();
        match &mut self.h {
            Handle::Disk(f) => f.set_len(pos.max(0) as u64).is_ok(),
            _ => false,
        }
    }

    pub fn prealloc(&mut self, _size: i64) {}

    pub fn is_device(&self) -> bool {
        match &self.h {
            Handle::Disk(f) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::FileTypeExt;
                    if let Ok(m) = f.metadata() {
                        return m.file_type().is_char_device();
                    }
                }
                let _ = f;
                false
            }
            _ => false,
        }
    }

    pub fn set_open_file_time(&mut self, _ftm: Option<&RarTime>, _ftc: Option<&RarTime>, _fta: Option<&RarTime>) {
        // Windows only. In Unix times are set after closing the file.
    }

    pub fn set_close_file_time(&self, ftm: Option<&RarTime>, fta: Option<&RarTime>) {
        set_close_file_time_by_name(&self.file_name, ftm, fta);
    }

    pub fn copy_to(&mut self, dest: &mut File, length: Option<i64>) -> i64 {
        let mut buf = vec![0u8; 0x100000];
        let mut copied = 0i64;
        let mut left = length;
        loop {
            crate::errhnd::wait();
            let n = match left {
                Some(l) if l <= 0 => break,
                Some(l) => (l as usize).min(buf.len()),
                None => buf.len(),
            };
            let r = self.read(&mut buf[..n]);
            if r <= 0 {
                break;
            }
            dest.write(&buf[..r as usize]);
            copied += r as i64;
            if let Some(l) = left.as_mut() {
                *l -= r as i64;
            }
        }
        copied
    }
}

/// Set modification and access time by file name.
pub fn set_close_file_time_by_name(name: &str, ftm: Option<&RarTime>, fta: Option<&RarTime>) {
    set_file_times_by_name(name, ftm, None, fta);
}

/// Set file or directory times. Creation time is supported in Windows only.
pub fn set_file_times_by_name(name: &str, ftm: Option<&RarTime>, ftc: Option<&RarTime>, fta: Option<&RarTime>) {
    let setm = ftm.map(|t| t.is_set()).unwrap_or(false);
    let setc = cfg!(windows) && ftc.map(|t| t.is_set()).unwrap_or(false);
    let seta = fta.map(|t| t.is_set()).unwrap_or(false);
    if !setm && !seta && !setc {
        return;
    }
    let path = to_path(name);
    let mut o = std::fs::OpenOptions::new();
    o.write(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_BACKUP_SEMANTICS is required to open directories,
        // FILE_FLAG_OPEN_REPARSE_POINT to set times of links themselves.
        o.custom_flags(0x02000000 | 0x00200000);
    }
    let f = o.open(&path).or_else(|_| std::fs::File::open(&path));
    if let Ok(f) = f {
        let mut t = std::fs::FileTimes::new();
        if cfg!(windows) {
            // Windows leaves omitted times unchanged.
            if setm {
                t = t.set_modified(ftm.unwrap().to_system_time());
            }
            if seta {
                t = t.set_accessed(fta.unwrap().to_system_time());
            }
            #[cfg(windows)]
            if setc {
                use std::os::windows::fs::FileTimesExt;
                t = t.set_created(ftc.unwrap().to_system_time());
            }
        } else {
            let now = std::time::SystemTime::now();
            t = t.set_modified(if setm { ftm.unwrap().to_system_time() } else { now });
            t = t.set_accessed(if seta { fta.unwrap().to_system_time() } else { now });
        }
        let _ = f.set_times(t);
    }
}
