// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Data input/output for decompression.

use crate::archive::Archive;
use crate::crypt::{CryptData, CryptMethod, CRYPT_BLOCK_MASK};
use crate::file::File;
use crate::hash::DataHash;
use crate::unpack::UnpackIo;

pub struct ComprDataIO {
    unpack_to_memory: bool,
    mem: Vec<u8>,
    mem_limit: usize,
    keep_last: bool,
    last_write: Vec<u8>,
    unp_packed_size: i64,
    unp_packed_left: i64,
    show_progress: bool,
    test_mode: bool,
    skip_unp_crc: bool,
    no_file_header: bool,
    sub_header: bool,
    decrypt: CryptData,
    last_percent: i32,
    current_command: char,
    pub decryption: bool,
    pub unp_volume: bool,
    pub next_volume_missing: bool,
    pub cur_pack_read: i64,
    pub cur_pack_write: i64,
    pub cur_unp_read: i64,
    pub cur_unp_write: i64,
    pub processed_arc_size: i64,
    pub last_arc_size: i64,
    pub total_arc_size: i64,
    pub packed_data_hash: DataHash,
    pub unp_hash: DataHash,
}

impl Default for ComprDataIO {
    fn default() -> Self {
        Self::new()
    }
}

impl ComprDataIO {
    pub fn new() -> Self {
        ComprDataIO {
            unpack_to_memory: false,
            mem: Vec::new(),
            mem_limit: 0,
            keep_last: false,
            last_write: Vec::new(),
            unp_packed_size: 0,
            unp_packed_left: 0,
            show_progress: true,
            test_mode: false,
            skip_unp_crc: false,
            no_file_header: false,
            sub_header: false,
            decrypt: CryptData::new(),
            last_percent: -1,
            current_command: '\0',
            decryption: false,
            unp_volume: false,
            next_volume_missing: false,
            cur_pack_read: 0,
            cur_pack_write: 0,
            cur_unp_read: 0,
            cur_unp_write: 0,
            processed_arc_size: 0,
            last_arc_size: 0,
            total_arc_size: 0,
            packed_data_hash: DataHash::default(),
            unp_hash: DataHash::default(),
        }
    }

    pub fn init(&mut self) {
        let total = self.total_arc_size;
        let processed = self.processed_arc_size;
        let last = self.last_arc_size;
        let cmd = self.current_command;
        *self = ComprDataIO::new();
        self.total_arc_size = total;
        self.processed_arc_size = processed;
        self.last_arc_size = last;
        self.current_command = cmd;
    }

    pub fn enable_show_progress(&mut self, s: bool) {
        self.show_progress = s;
    }
    pub fn set_packed_size_to_read(&mut self, size: i64) {
        self.unp_packed_size = size;
        self.unp_packed_left = size;
    }
    pub fn set_test_mode(&mut self, m: bool) {
        self.test_mode = m;
    }
    pub fn set_skip_unp_crc(&mut self, s: bool) {
        self.skip_unp_crc = s;
    }
    pub fn set_no_file_header(&mut self, m: bool) {
        self.no_file_header = m;
    }
    pub fn set_sub_header(&mut self, s: bool) {
        self.sub_header = s;
    }
    pub fn set_current_command(&mut self, c: char) {
        self.current_command = c;
    }
    pub fn reset_percent(&mut self) {
        self.last_percent = -1;
    }
    pub fn set_unpack_to_memory(&mut self, size: usize) {
        self.unpack_to_memory = true;
        self.mem = Vec::with_capacity(size);
        self.mem_limit = size;
    }
    pub fn take_memory(&mut self) -> Vec<u8> {
        let mut m = std::mem::take(&mut self.mem);
        m.resize(self.mem_limit, 0);
        m
    }
    pub fn keep_last_write(&mut self, k: bool) {
        self.keep_last = k;
    }
    pub fn last_write(&self) -> Vec<u8> {
        self.last_write.clone()
    }

    pub fn set_encryption(&mut self, method: CryptMethod, pwd: &str, salt: Option<&[u8]>, init_v: &[u8; 16], lg2: u32) -> Option<crate::crypt::Rar5Keys> {
        let r = self.decrypt.set_keys(method, pwd, salt, Some(init_v), lg2);
        self.decryption = r.is_some();
        r
    }

    pub fn clear_encryption(&mut self) {
        self.decryption = false;
    }

    pub fn set_cmt13_encryption(&mut self) {
        self.decryption = true;
        self.decrypt.set_cmt13_encryption();
    }

    /// Read packed data, switching volumes if necessary.
    pub fn unp_read(&mut self, buf: &mut [u8], arc: &mut Archive) -> i32 {
        let mut count = buf.len();
        if self.decryption {
            count &= !CRYPT_BLOCK_MASK;
        }
        let mut read_size: i32 = 0;
        let mut total_read: usize = 0;
        while count > 0 {
            let mut size_to_read = if count as i64 > self.unp_packed_left { self.unp_packed_left.max(0) as usize } else { count };
            if size_to_read > 0 {
                if self.unp_volume && self.decryption && count as i64 > self.unp_packed_left {
                    let new_total = total_read + size_to_read;
                    let adjust = new_total - (new_total & !CRYPT_BLOCK_MASK);
                    let new_size = size_to_read.wrapping_sub(adjust);
                    if (new_size as isize) > 0 {
                        size_to_read = new_size;
                    }
                }
                if !arc.is_opened() {
                    return -1;
                }
                read_size = arc.read(&mut buf[total_read..total_read + size_to_read]);
                let split_after = if self.sub_header { arc.sub_head.split_after } else { arc.file_head.split_after };
                if !self.no_file_header && split_after && read_size > 0 {
                    self.packed_data_hash.update(&buf[total_read..total_read + read_size as usize]);
                }
            } else {
                read_size = 0;
            }
            let rs = read_size.max(0) as usize;
            self.cur_unp_read += rs as i64;
            total_read += rs;
            count -= rs.min(count);
            self.unp_packed_left -= rs as i64;
            if self.unp_volume
                && self.unp_packed_left == 0
                && (read_size == 0 || self.decryption && (total_read & CRYPT_BLOCK_MASK) != 0)
            {
                let cmd = self.current_command;
                if !crate::volume::merge_archive(arc, Some(self), true, cmd) {
                    self.next_volume_missing = true;
                    return -1;
                }
            } else {
                break;
            }
        }
        let pos = arc.next_block_pos - self.unp_packed_size + self.cur_unp_read;
        self.show_unp_read(pos, arc);
        if read_size != -1 {
            if self.decryption {
                self.decrypt.decrypt(&mut buf[..total_read]);
            }
            read_size = total_read as i32;
        }
        crate::errhnd::wait();
        read_size
    }

    fn show_unp_read(&mut self, arc_pos: i64, arc: &Archive) {
        if self.show_progress {
            let arc_pos = arc_pos + self.processed_arc_size;
            let cur = crate::ui::to_percent(arc_pos, self.total_arc_size);
            let disable = arc.cmd().borrow().disable_percentage;
            if !disable && cur != self.last_percent {
                crate::ui::ui_extract_progress(self.cur_unp_write, arc.file_head.unp_size, arc_pos, self.total_arc_size);
                self.last_percent = cur;
            }
        }
    }

    /// Write unpacked data.
    pub fn unp_write(&mut self, data: &[u8], dest: Option<&mut File>) {
        if self.keep_last {
            self.last_write = data.to_vec();
        }
        if self.unpack_to_memory {
            if self.mem.len() + data.len() <= self.mem_limit {
                self.mem.extend_from_slice(data);
            }
        } else if !self.test_mode {
            if let Some(d) = dest {
                d.write(data);
            }
        }
        self.cur_unp_write += data.len() as i64;
        if !self.skip_unp_crc {
            self.unp_hash.update(data);
        }
        crate::errhnd::wait();
    }

    /// Adjust total archive size, excluding trailing service blocks.
    pub fn adjust_total_arc_size(&mut self, arc: &mut Archive) {
        let arc_length = if arc.is_seekable() { arc.file_length() as u64 } else { 0 };
        if arc.main_head.qopen_offset > 0 && arc.main_head.qopen_offset < arc_length {
            self.last_arc_size = arc.main_head.qopen_offset as i64;
        } else if arc.main_head.rr_offset > 0 && arc.main_head.rr_offset < arc_length {
            self.last_arc_size = arc.main_head.rr_offset as i64;
        } else {
            const END_BLOCK: u64 = 23;
            if arc_length > END_BLOCK {
                self.last_arc_size = (arc_length - END_BLOCK) as i64;
            }
        }
        self.total_arc_size -= arc_length as i64 - self.last_arc_size;
    }
}

/// Connects ComprDataIO with archive and destination file for Unpack.
pub struct DataIoCtx<'a> {
    pub io: &'a mut ComprDataIO,
    pub arc: &'a mut Archive,
    pub dest: Option<&'a mut File>,
}

impl UnpackIo for DataIoCtx<'_> {
    fn unp_read(&mut self, buf: &mut [u8]) -> i32 {
        self.io.unp_read(buf, self.arc)
    }
    fn unp_write(&mut self, data: &[u8]) {
        self.io.unp_write(data, self.dest.as_deref_mut());
    }
}
