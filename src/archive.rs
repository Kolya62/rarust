// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Archive: signature detection and header reading for all RAR formats.

use crate::cmddata::{CmdRef, QOpenMode, NAMES_LOWERCASE, NAMES_UPPERCASE};
use crate::crypt::*;
use crate::errhnd::{self, *};
use crate::file::{File, SEEK_END, SEEK_SET};
use crate::hash::sha256::Sha256;
use crate::hash::HashType;
use crate::headers::*;
use crate::pathfn::CPATHDIVIDER;
use crate::rawread::RawRead;
use crate::rdwrfn::{ComprDataIO, DataIoCtx};
use crate::strfn::{wcslower, wcsupper};
use crate::ui::{ui_msg, UiMsg};
use crate::unicode::{char_to_wide, oem_to_wide, utf_to_wide};
use crate::unpack::Unpack;

pub const MAX_HEADER_SIZE_RAR5: usize = 0x200000;
const MAXSFXSIZE: usize = 0x400000;
const MAXPATHSIZE: usize = 0x10000;
const UNPACK_MAX_DICT: u64 = 0x1000000000;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum RarFormat {
    #[default]
    None,
    Rar14,
    Rar15,
    Rar50,
    Future,
}

/// Quick open state: cached copy of archive headers stored in archive end.
#[derive(Default)]
struct QuickOpen {
    loaded: bool,
    buf: Vec<u8>,
    crypt: CryptData,
    encrypted: bool,
    qo_header_pos: u64,
    raw_data_start: u64,
    raw_data_size: u64,
    raw_data_pos: u64,
    read_buf_size: usize,
    read_buf_pos: usize,
    last_read_header: Vec<u8>,
    last_read_header_pos: u64,
    seek_pos: u64,
    unsync_seek_pos: bool,
}

const QO_MAX_BUF_SIZE: usize = 0x10000;

pub struct Archive {
    pub file: File,
    cmd: CmdRef,
    headers_crypt: CryptData,
    recovery_percent: i32,
    cur_header_type: u32,
    silent_open: bool,
    qopen: QuickOpen,
    prohibit_qopen: bool,

    pub short_block: BaseBlock,
    pub mark_head: [u8; 8],
    pub mark_head_size: u32,
    pub main_head: MainHeader,
    pub crypt_head: CryptHeader,
    pub file_head: FileHeader,
    pub end_arc_head: EndArcHeader,
    pub sub_block_head: SubBlockHeader,
    pub sub_head: FileHeader,
    pub comm_head: CommentHeader,
    pub protect_head: ProtectHeader,
    pub ea_head: EaHeader,
    pub stream_head: StreamHeader,
    pub motw: crate::motw::MarkOfTheWeb,
    pub cur_block_pos: i64,
    pub next_block_pos: i64,
    pub format: RarFormat,
    pub solid: bool,
    pub volume: bool,
    pub main_comment: bool,
    pub locked: bool,
    pub signed: bool,
    pub first_volume: bool,
    pub new_numbering: bool,
    pub protected: bool,
    pub encrypted: bool,
    pub sfx_size: usize,
    pub broken_header: bool,
    pub failed_header_decryption: bool,
    pub vol_number: u32,
    pub first_volume_name: String,
}

fn safe_add(v1: i64, v2: i64, f: i64) -> i64 {
    if v1 >= 0 && v2 >= 0 && v1 <= i64::MAX - v2 {
        v1 + v2
    } else {
        f
    }
}

/// Return 0 if dictionary size is invalid. Return the adjusted value and
/// header flags otherwise.
pub fn get_win_size(size: u64) -> (u64, u32) {
    let mut flags = 0;
    if !(0x20000..=0x10000000000).contains(&size) {
        return (0, 0);
    }
    let mut pow2: u64 = 0x20000;
    while 2 * pow2 <= size {
        pow2 *= 2;
        flags += FCI_DICT_BIT0;
    }
    if size == pow2 {
        return (size, flags);
    }
    let fraction = (size - pow2) / (pow2 / 32);
    flags += fraction as u32 * FCI_DICT_FRACT0;
    (pow2 + fraction * (pow2 / 32), flags)
}

pub fn is_signature(d: &[u8]) -> RarFormat {
    let mut t = RarFormat::None;
    if !d.is_empty() && d[0] == 0x52 {
        if d.len() >= 4 && d[1] == 0x45 && d[2] == 0x7e && d[3] == 0x5e {
            t = RarFormat::Rar14;
        } else if d.len() >= 7 && d[1] == 0x61 && d[2] == 0x72 && d[3] == 0x21 && d[4] == 0x1a && d[5] == 0x07 {
            if d[6] == 0 {
                t = RarFormat::Rar15;
            } else if d[6] == 1 {
                t = RarFormat::Rar50;
            } else if d[6] > 1 && d[6] < 5 {
                t = RarFormat::Future;
            }
        }
    }
    t
}

impl Archive {
    pub fn new(cmd: CmdRef) -> Archive {
        let open_shared = cmd.borrow().open_shared;
        let mut file = File::new();
        file.open_shared = open_shared;
        Archive {
            file,
            cmd,
            headers_crypt: CryptData::new(),
            recovery_percent: -1,
            cur_header_type: HEAD_UNKNOWN,
            silent_open: false,
            qopen: QuickOpen::default(),
            prohibit_qopen: false,
            short_block: BaseBlock::default(),
            mark_head: [0; 8],
            mark_head_size: 0,
            main_head: MainHeader::default(),
            crypt_head: CryptHeader::default(),
            file_head: FileHeader::default(),
            end_arc_head: EndArcHeader::default(),
            sub_block_head: SubBlockHeader::default(),
            sub_head: FileHeader::default(),
            comm_head: CommentHeader::default(),
            protect_head: ProtectHeader::default(),
            ea_head: EaHeader::default(),
            stream_head: StreamHeader::default(),
            motw: Default::default(),
            cur_block_pos: 0,
            next_block_pos: 0,
            format: RarFormat::None,
            solid: false,
            volume: false,
            main_comment: false,
            locked: false,
            signed: false,
            first_volume: false,
            new_numbering: false,
            protected: false,
            encrypted: false,
            sfx_size: 0,
            broken_header: false,
            failed_header_decryption: false,
            vol_number: 0,
            first_volume_name: String::new(),
        }
    }

    pub fn cmd(&self) -> &CmdRef {
        &self.cmd
    }

    pub fn file_name(&self) -> &str {
        &self.file.file_name
    }

    pub fn get_header_type(&self) -> u32 {
        self.cur_header_type
    }

    pub fn get_recovery_percent(&self) -> i32 {
        self.recovery_percent
    }

    pub fn set_silent_open(&mut self, m: bool) {
        self.silent_open = m;
    }

    pub fn set_prohibit_qopen(&mut self, m: bool) {
        self.prohibit_qopen = m;
    }

    // File access with quick open support.

    pub fn open(&mut self, name: &str, mode: u32) -> bool {
        self.qopen.loaded = false;
        self.file.open(name, mode)
    }

    pub fn w_open(&mut self, name: &str) -> bool {
        self.qopen.loaded = false;
        self.file.w_open(name)
    }

    pub fn close(&mut self) {
        self.file.close();
    }

    pub fn is_opened(&self) -> bool {
        self.file.is_opened()
    }

    pub fn is_seekable(&self) -> bool {
        self.file.is_seekable()
    }

    pub fn read(&mut self, buf: &mut [u8]) -> i32 {
        if let Some(r) = self.qo_read(buf) {
            return r as i32;
        }
        self.file.read(buf)
    }

    pub fn seek(&mut self, offset: i64, method: i32) {
        if !self.qo_seek(offset, method) {
            self.file.seek(offset, method);
        }
    }

    pub fn tell(&mut self) -> i64 {
        if self.qopen.loaded {
            return self.qopen.seek_pos as i64;
        }
        self.file.tell()
    }

    pub fn file_length(&mut self) -> i64 {
        self.file.file_length()
    }

    pub fn get_byte(&mut self) -> u8 {
        let mut b = [0u8; 1];
        self.read(&mut b);
        b[0]
    }

    pub fn seek_to_next(&mut self) {
        let p = self.next_block_pos;
        self.seek(p, SEEK_SET);
    }

    pub fn check_arc(&mut self, enable_broken: bool) {
        if !self.is_archive(enable_broken) {
            if !self.failed_header_decryption {
                ui_msg(UiMsg::BadArchive(self.file_name().to_string()));
            }
            errhnd::exit(RARX_BADARC);
        }
    }

    pub fn w_check_open(&mut self, name: &str) -> bool {
        if !self.w_open(name) {
            return false;
        }
        if !self.is_archive(false) {
            ui_msg(UiMsg::BadArchive(self.file_name().to_string()));
            self.close();
            return false;
        }
        true
    }

    pub fn is_archive(&mut self, enable_broken: bool) -> bool {
        self.encrypted = false;
        self.broken_header = false;
        if self.file.is_device() {
            let n = self.file_name().to_string();
            ui_msg(UiMsg::InvalidName(n.clone(), n));
            return false;
        }
        let mut mark = [0u8; 8];
        if self.read(&mut mark[..SIZEOF_MARKHEAD3]) != SIZEOF_MARKHEAD3 as i32 {
            return false;
        }
        self.mark_head = mark;
        self.sfx_size = 0;
        let t = is_signature(&mark[..SIZEOF_MARKHEAD3]);
        if t != RarFormat::None {
            self.format = t;
            if t == RarFormat::Rar14 {
                let p = self.tell() - SIZEOF_MARKHEAD3 as i64;
                self.seek(p, SEEK_SET);
            }
        } else {
            let mut buffer = vec![0u8; MAXSFXSIZE];
            let cur_pos: usize = 1;
            self.seek(cur_pos as i64, SEEK_SET);
            let read_size = self.read(&mut buffer[..MAXSFXSIZE - 16]).max(0) as usize;
            let mut i = 0;
            while i < read_size {
                if buffer[i] == 0x52 {
                    let t = is_signature(&buffer[i..read_size]);
                    if t != RarFormat::None {
                        self.format = t;
                        if t == RarFormat::Rar14 && i > 0 && cur_pos < 28 && read_size > 31 {
                            let d = &buffer[28 - cur_pos..];
                            if d[0] != 0x52 || d[1] != 0x53 || d[2] != 0x46 || d[3] != 0x58 {
                                i += 1;
                                continue;
                            }
                        }
                        self.sfx_size = cur_pos + i;
                        let s = self.sfx_size as i64;
                        self.seek(s, SEEK_SET);
                        if t == RarFormat::Rar15 || t == RarFormat::Rar50 {
                            let mut m = [0u8; 8];
                            self.read(&mut m[..SIZEOF_MARKHEAD3]);
                            self.mark_head = m;
                        }
                        break;
                    }
                }
                i += 1;
            }
            if self.sfx_size == 0 {
                return false;
            }
        }
        if self.format == RarFormat::Future {
            ui_msg(UiMsg::NewRarFormat(self.file_name().to_string()));
            return false;
        }
        if self.format == RarFormat::Rar50 {
            let mut b = [0u8; 1];
            if self.read(&mut b) != 1 || b[0] != 0 {
                return false;
            }
            self.mark_head[SIZEOF_MARKHEAD3] = 0;
            self.mark_head_size = SIZEOF_MARKHEAD5 as u32;
        } else {
            self.mark_head_size = SIZEOF_MARKHEAD3 as u32;
        }

        let mut headers_left;
        let mut start_found = false;
        loop {
            headers_left = self.read_header() != 0;
            if !headers_left {
                break;
            }
            self.seek_to_next();
            let t = self.get_header_type();
            start_found = t == HEAD_MAIN || self.silent_open && t == HEAD_CRYPT;
            if start_found {
                break;
            }
        }
        if self.failed_header_decryption && !enable_broken {
            return false;
        }
        if self.broken_header || !start_found {
            if !self.failed_header_decryption {
                ui_msg(UiMsg::MainHeaderBroken(self.file_name().to_string()));
            }
            if !enable_broken {
                return false;
            }
        }
        self.main_comment = self.main_head.comment_in_header;
        if headers_left && (!self.silent_open || !self.encrypted) && self.is_seekable() {
            let save_pos = self.tell();
            let save_cur = self.cur_block_pos;
            let save_next = self.next_block_pos;
            let save_type = self.cur_header_type;
            while self.read_header() != 0 {
                let ht = self.get_header_type();
                if ht == HEAD_SERVICE {
                    self.first_volume = self.volume && !self.sub_head.split_before;
                } else if ht == HEAD_FILE {
                    self.first_volume = self.volume && !self.file_head.split_before;
                    break;
                } else if ht == HEAD_ENDARC {
                    break;
                }
                self.seek_to_next();
            }
            self.cur_block_pos = save_cur;
            self.next_block_pos = save_next;
            self.cur_header_type = save_type;
            self.seek(save_pos, SEEK_SET);
        }
        if !self.volume || self.first_volume {
            self.first_volume_name = self.file_name().to_string();
        }
        true
    }

    /// Calculate the block size including encryption fields and padding.
    pub fn full_header_size(&self, size: usize) -> u32 {
        let mut size = size;
        if self.encrypted {
            size = size + ((!size).wrapping_add(1) & CRYPT_BLOCK_MASK);
            if self.format == RarFormat::Rar50 {
                size += SIZE_INITV;
            } else {
                size += SIZE_SALT30;
            }
        }
        size as u32
    }

    pub fn read_header(&mut self) -> usize {
        if self.failed_header_decryption {
            return 0;
        }
        self.cur_block_pos = self.tell();
        let mut read_size = match self.format {
            RarFormat::Rar14 => self.read_header14(),
            RarFormat::Rar15 => self.read_header15(),
            RarFormat::Rar50 => self.read_header50(),
            _ => 0,
        };
        if read_size > 0 && self.next_block_pos <= self.cur_block_pos {
            self.broken_header_msg();
            read_size = 0;
        }
        if read_size == 0 {
            self.cur_header_type = HEAD_UNKNOWN;
        }
        read_size
    }

    pub fn search_block(&mut self, header_type: u32) -> usize {
        let mut count = 0u32;
        loop {
            let size = self.read_header();
            if size == 0 || header_type != HEAD_ENDARC && self.get_header_type() == HEAD_ENDARC {
                return 0;
            }
            count += 1;
            if count & 127 == 0 {
                errhnd::wait();
            }
            if self.get_header_type() == header_type {
                return size;
            }
            self.seek_to_next();
        }
    }

    pub fn search_sub_block(&mut self, t: &str) -> usize {
        let mut count = 0u32;
        loop {
            let size = self.read_header();
            if size == 0 || self.get_header_type() == HEAD_ENDARC {
                return 0;
            }
            count += 1;
            if count & 127 == 0 {
                errhnd::wait();
            }
            if self.get_header_type() == HEAD_SERVICE && self.sub_head.cmp_name(t) {
                return size;
            }
            self.seek_to_next();
        }
    }

    pub fn search_rr(&mut self) -> usize {
        if self.main_head.locator && self.main_head.rr_offset != 0 {
            let cur = self.tell();
            let p = self.main_head.rr_offset as i64;
            self.seek(p, SEEK_SET);
            let size = self.read_header();
            if size != 0 && !self.broken_header && self.get_header_type() == HEAD_SERVICE && self.sub_head.cmp_name(SUBHEAD_TYPE_RR) {
                return size;
            }
            self.seek(cur, SEEK_SET);
        }
        self.search_sub_block(SUBHEAD_TYPE_RR)
    }

    fn unexp_end_arc_msg(&mut self) {
        let arc_size = self.file_length();
        if self.cur_block_pos != arc_size || self.next_block_pos != arc_size {
            ui_msg(UiMsg::UnexpEof(self.file_name().to_string()));
            if self.cur_header_type != HEAD_FILE && self.cur_header_type != HEAD_UNKNOWN {
                ui_msg(UiMsg::TruncService(self.file_name().to_string(), self.sub_head.file_name.clone()));
            }
            set_error_code(RARX_WARNING);
        }
    }

    fn broken_header_msg(&mut self) {
        ui_msg(UiMsg::HeaderBroken(self.file_name().to_string()));
        self.broken_header = true;
        set_error_code(RARX_CRC);
    }

    fn unk_enc_ver_msg(&self, name: &str, info: &str) {
        ui_msg(UiMsg::UnknownEncMethod(self.file_name().to_string(), name.to_string(), info.to_string()));
        set_error_code(RARX_FATAL);
    }

    /// Read `size` bytes into raw buffer, decrypting with headers key if set.
    fn raw_read(&mut self, raw: &mut RawRead, size: usize, decrypt: bool) -> usize {
        if decrypt {
            let mut hc = std::mem::take(&mut self.headers_crypt);
            let r = raw.read_from(size, Some(&mut hc), &mut |b| self.read(b));
            self.headers_crypt = hc;
            r
        } else {
            raw.read_from(size, None, &mut |b| self.read(b))
        }
    }

    fn request_arc_password(&mut self) {
        if !self.cmd.borrow().password_set() {
            let name = self.file_name().to_string();
            match crate::consio::get_console_password(crate::consio::PasswordType::Archive, &name) {
                Some(p) if !p.is_empty() => {
                    let mut c = self.cmd.borrow_mut();
                    c.password = Some(p);
                    c.manual_password = true;
                }
                _ => {
                    self.close();
                    ui_msg(UiMsg::IncErrCount);
                    errhnd::exit(RARX_USERBREAK);
                }
            }
        }
    }

    fn password(&self) -> String {
        self.cmd.borrow().password.clone().unwrap_or_default()
    }

    fn read_header15(&mut self) -> usize {
        let mut raw = RawRead::new();
        let decrypt = self.encrypted && self.cur_block_pos > (self.sfx_size + SIZEOF_MARKHEAD3) as i64;
        if decrypt {
            self.request_arc_password();
            let mut salt = [0u8; SIZE_SALT30];
            if self.read(&mut salt) != SIZE_SALT30 as i32 {
                self.unexp_end_arc_msg();
                return 0;
            }
            let pwd = self.password();
            self.headers_crypt.set_keys(CryptMethod::Rar30, &pwd, Some(&salt), None, 0);
        }
        self.raw_read(&mut raw, SIZEOF_SHORTBLOCKHEAD, decrypt);
        if raw.size() == 0 {
            self.unexp_end_arc_msg();
            return 0;
        }
        let mut sb = BaseBlock { head_crc: raw.get2() as u32, ..Default::default() };
        let header_type = raw.get1() as u32;
        sb.flags = raw.get2() as u32;
        sb.skip_if_unknown = sb.flags & SKIP_IF_UNKNOWN != 0;
        sb.head_size = raw.get2() as u32;
        sb.header_type = header_type;
        if (sb.head_size as usize) < SIZEOF_SHORTBLOCKHEAD {
            self.short_block = sb;
            self.broken_header_msg();
            return 0;
        }
        sb.header_type = match sb.header_type {
            HEAD3_MAIN => HEAD_MAIN,
            HEAD3_FILE => HEAD_FILE,
            HEAD3_SERVICE => HEAD_SERVICE,
            HEAD3_ENDARC => HEAD_ENDARC,
            t => t,
        };
        self.cur_header_type = sb.header_type;
        if sb.header_type == HEAD3_CMT {
            self.raw_read(&mut raw, SIZEOF_COMMHEAD - SIZEOF_SHORTBLOCKHEAD, decrypt);
        } else if sb.header_type == HEAD_MAIN && (sb.flags & MHD_COMMENT) != 0 {
            self.raw_read(&mut raw, SIZEOF_MAINHEAD3 - SIZEOF_SHORTBLOCKHEAD, decrypt);
        } else {
            self.raw_read(&mut raw, sb.head_size as usize - SIZEOF_SHORTBLOCKHEAD, decrypt);
        }
        self.short_block = sb.clone();
        self.next_block_pos = self.cur_block_pos + self.full_header_size(sb.head_size as usize) as i64;

        match sb.header_type {
            HEAD_MAIN => {
                self.main_head = MainHeader { base: sb.clone(), ..Default::default() };
                self.main_head.high_pos_av = raw.get2();
                self.main_head.pos_av = raw.get4();
                let f = sb.flags;
                self.volume = f & MHD_VOLUME != 0;
                self.solid = f & MHD_SOLID != 0;
                self.locked = f & MHD_LOCK != 0;
                self.protected = f & MHD_PROTECT != 0;
                self.encrypted = f & MHD_PASSWORD != 0;
                self.signed = self.main_head.pos_av != 0 || self.main_head.high_pos_av != 0;
                self.main_head.comment_in_header = f & MHD_COMMENT != 0;
                self.first_volume = f & MHD_FIRSTVOLUME != 0;
                self.new_numbering = f & MHD_NEWNUMBERING != 0;
            }
            HEAD_FILE | HEAD_SERVICE => {
                let file_block = sb.header_type == HEAD_FILE;
                let mut hd = if file_block { &self.file_head } else { &self.sub_head }.reset_copy(sb.clone());
                let f = sb.flags;
                hd.split_before = f & LHD_SPLIT_BEFORE != 0;
                hd.split_after = f & LHD_SPLIT_AFTER != 0;
                hd.encrypted = f & LHD_PASSWORD != 0;
                hd.salt_set = f & LHD_SALT != 0;
                hd.solid = file_block && f & LHD_SOLID != 0;
                hd.sub_block = !file_block && f & LHD_SOLID != 0;
                hd.dir = f & LHD_WINDOWMASK == LHD_DIRECTORY;
                hd.win_size = if hd.dir { 0 } else { 0x10000u64 << ((f & LHD_WINDOWMASK) >> 5) };
                hd.comment_in_header = f & LHD_COMMENT != 0;
                hd.version = f & LHD_VERSION != 0;
                hd.data_size = raw.get4();
                let low_unp_size = raw.get4();
                hd.host_os = raw.get1();
                hd.file_hash.kind = HashType::Crc32;
                hd.file_hash.crc32 = raw.get4();
                let file_time = raw.get4();
                hd.unp_ver = raw.get1() as u32;
                hd.method = (raw.get1() as u32).wrapping_sub(0x30);
                let name_size = raw.get2() as usize;
                hd.file_attr = raw.get4();
                if hd.unp_ver < 20 && (hd.file_attr & 0x10) != 0 {
                    hd.dir = true;
                }
                hd.crypt_method = CryptMethod::None;
                if hd.encrypted {
                    hd.crypt_method = match hd.unp_ver {
                        13 => CryptMethod::Rar13,
                        15 => CryptMethod::Rar15,
                        20 | 26 => CryptMethod::Rar20,
                        _ => CryptMethod::Rar30,
                    };
                }
                hd.hs_type = HostSystemType::Unknown;
                if hd.host_os == HOST_UNIX || hd.host_os == HOST_BEOS {
                    hd.hs_type = HostSystemType::Unix;
                } else if hd.host_os < HOST_MAX {
                    hd.hs_type = HostSystemType::Windows;
                }
                hd.redir_type = FsRedir::None;
                if hd.host_os == HOST_UNIX && (hd.file_attr & 0xF000) == 0xA000 {
                    hd.redir_type = FsRedir::UnixSymlink;
                    hd.redir_name.clear();
                }
                hd.inherited = !file_block && (hd.file_attr & SUBHEAD_FLAGS_INHERITED) != 0;
                hd.large_file = f & LHD_LARGE != 0;
                let (high_pack, high_unp);
                if hd.large_file {
                    high_pack = raw.get4();
                    high_unp = raw.get4();
                    hd.unknown_unp_size = low_unp_size == 0xffffffff && high_unp == 0xffffffff;
                } else {
                    high_pack = 0;
                    high_unp = 0;
                    hd.unknown_unp_size = low_unp_size == 0xffffffff;
                }
                hd.pack_size = ((high_pack as u64) << 32 | hd.data_size as u64) as i64;
                hd.unp_size = ((high_unp as u64) << 32 | low_unp_size as u64) as i64;
                if hd.unknown_unp_size {
                    hd.unp_size = INT64NDF;
                }
                let read_name_size = name_size.min(MAXPATHSIZE);
                let file_name = raw.getb_vec(read_name_size);
                if file_block {
                    hd.file_name.clear();
                    if f & LHD_UNICODE != 0 {
                        let length = file_name.iter().position(|&b| b == 0).unwrap_or(file_name.len()) + 1;
                        if read_name_size > length {
                            hd.file_name = crate::encname::decode(&file_name, &file_name[length..]);
                        }
                    }
                    if hd.file_name.is_empty() {
                        hd.file_name = oem_to_wide(&file_name);
                    }
                    self.convert_name_case(&mut hd.file_name);
                    self.convert_file_header(&mut hd);
                } else {
                    hd.file_name = char_to_wide(&file_name);
                    let mut data_size = hd.base.head_size as i64 - name_size as i64 - SIZEOF_FILEHEAD3 as i64;
                    if f & LHD_SALT != 0 {
                        data_size -= SIZE_SALT30 as i64;
                    }
                    if data_size > 0 {
                        hd.sub_data = raw.getb_vec(data_size as usize);
                    }
                    if hd.cmp_name(SUBHEAD_TYPE_CMT) {
                        self.main_comment = true;
                    }
                }
                if f & LHD_SALT != 0 {
                    raw.getb(&mut hd.salt[..SIZE_SALT30]);
                }
                hd.mtime.set_dos(file_time);
                if f & LHD_EXTTIME != 0 {
                    // Extended times are always stored in file header times.
                    if file_block {
                        self.file_head.mtime = hd.mtime;
                        self.file_head.ctime = Default::default();
                        self.file_head.atime = Default::default();
                    }
                    let flags = raw.get2() as u32;
                    for i in 0..4 {
                        let rmode = flags >> ((3 - i) * 4);
                        if rmode & 8 == 0 || i == 3 {
                            continue;
                        }
                        let cur_time = match i {
                            0 => &mut self.file_head.mtime,
                            1 => &mut self.file_head.ctime,
                            _ => &mut self.file_head.atime,
                        };
                        if i != 0 {
                            let dos = raw.get4();
                            cur_time.set_dos(dos);
                        }
                        let mut rlt = cur_time.get_local();
                        if rmode & 4 != 0 {
                            rlt.second += 1;
                        }
                        rlt.reminder = 0;
                        let count = rmode & 3;
                        for j in 0..count {
                            let b = raw.get1() as u32;
                            rlt.reminder |= b << ((j + 3 - count) * 8);
                        }
                        rlt.reminder *= crate::timefn::REMINDER_PRECISION / 10_000_000;
                        cur_time.set_local(&rlt);
                    }
                    if file_block {
                        hd.mtime = self.file_head.mtime;
                        hd.ctime = self.file_head.ctime;
                        hd.atime = self.file_head.atime;
                    }
                }
                self.next_block_pos = safe_add(self.next_block_pos, hd.pack_size, 0);
                let crc_processed_only = hd.comment_in_header;
                let header_crc = raw.get_crc15(crc_processed_only);
                if hd.base.head_crc != header_crc {
                    self.broken_header = true;
                    set_error_code(RARX_WARNING);
                    if !decrypt {
                        ui_msg(UiMsg::FHeaderBroken(self.file_name().to_string(), hd.file_name.clone()));
                    }
                }
                if file_block {
                    self.file_head = hd;
                } else {
                    self.sub_head = hd;
                }
            }
            HEAD_ENDARC => {
                let f = sb.flags;
                self.end_arc_head = EndArcHeader {
                    base: sb.clone(),
                    next_volume: f & EARC_NEXT_VOLUME != 0,
                    data_crc: f & EARC_DATACRC != 0,
                    rev_space: f & EARC_REVSPACE != 0,
                    store_vol_number: f & EARC_VOLNUMBER != 0,
                    ..Default::default()
                };
                if self.end_arc_head.data_crc {
                    self.end_arc_head.arc_data_crc = raw.get4();
                }
                if self.end_arc_head.store_vol_number {
                    let v = raw.get2() as u32;
                    self.end_arc_head.vol_number = v;
                    self.vol_number = v;
                }
            }
            HEAD3_CMT => {
                self.comm_head = CommentHeader {
                    base: sb.clone(),
                    unp_size: raw.get2(),
                    unp_ver: raw.get1(),
                    method: raw.get1(),
                    comm_crc: raw.get2(),
                };
            }
            HEAD3_PROTECT => {
                let mut ph = ProtectHeader { base: sb.clone(), ..Default::default() };
                ph.data_size = raw.get4();
                ph.version = raw.get1();
                ph.rec_sectors = raw.get2();
                ph.total_blocks = raw.get4();
                raw.getb(&mut ph.mark);
                self.next_block_pos += ph.data_size as i64;
                self.protect_head = ph;
            }
            HEAD3_OLDSERVICE => {
                let mut sbh = SubBlockHeader { base: sb.clone(), ..Default::default() };
                sbh.data_size = raw.get4();
                self.next_block_pos += sbh.data_size as i64;
                sbh.sub_type = raw.get2();
                sbh.level = raw.get1();
                match sbh.sub_type {
                    NTACL_HEAD => {
                        self.ea_head = EaHeader {
                            sub: sbh.clone(),
                            unp_size: raw.get4(),
                            unp_ver: raw.get1(),
                            method: raw.get1(),
                            ea_crc: raw.get4(),
                        };
                    }
                    STREAM_HEAD => {
                        let mut st = StreamHeader { sub: sbh.clone(), ..Default::default() };
                        st.unp_size = raw.get4();
                        st.unp_ver = raw.get1();
                        st.method = raw.get1();
                        st.stream_crc = raw.get4();
                        st.stream_name_size = raw.get2().min(260);
                        st.stream_name = raw.getb_vec(st.stream_name_size as usize);
                        self.stream_head = st;
                    }
                    _ => {}
                }
                self.sub_block_head = sbh;
            }
            _ => {
                if sb.flags & LONG_BLOCK != 0 {
                    self.next_block_pos += raw.get4() as i64;
                }
            }
        }

        let header_crc = raw.get_crc15(false);
        if sb.head_crc != header_crc
            && sb.header_type != HEAD3_SIGN
            && sb.header_type != HEAD3_AV
            && (sb.header_type != HEAD3_OLDSERVICE || self.sub_block_head.sub_type != UO_HEAD)
        {
            let mut recovered = false;
            if sb.header_type == HEAD_ENDARC && self.end_arc_head.rev_space {
                let length = self.tell();
                self.seek(length - 7, SEEK_SET);
                recovered = true;
                for _ in 0..7 {
                    if self.get_byte() != 0 {
                        recovered = false;
                    }
                }
            }
            if !recovered {
                self.broken_header = true;
                set_error_code(RARX_CRC);
                if decrypt {
                    let n = self.file_name().to_string();
                    ui_msg(UiMsg::ChecksumEnc(n.clone(), n));
                    self.failed_header_decryption = true;
                    return 0;
                }
            }
        }
        raw.size()
    }

    fn read_header50(&mut self) -> usize {
        let mut raw = RawRead::new();
        let decrypt = self.encrypted && self.cur_block_pos > (self.sfx_size + SIZEOF_MARKHEAD5) as i64;
        if decrypt {
            if self.cmd.borrow().skip_encrypted {
                ui_msg(UiMsg::SkipEncArc(self.file_name().to_string()));
                self.failed_header_decryption = true;
                return 0;
            }
            let mut init_v = [0u8; SIZE_INITV];
            if self.read(&mut init_v) != SIZE_INITV as i32 {
                self.unexp_end_arc_msg();
                return 0;
            }
            let global_password = self.cmd.borrow().password_set();
            let use_check = self.crypt_head.use_psw_check && !self.broken_header;
            loop {
                self.request_arc_password();
                let pwd = self.password();
                let ch = self.crypt_head.clone();
                let keys = self.headers_crypt.set_keys(CryptMethod::Rar50, &pwd, Some(&ch.salt), Some(&init_v), ch.lg2_count);
                if let Some(k) = keys {
                    if use_check && k.psw_check != ch.psw_check {
                        let n = self.file_name().to_string();
                        if global_password {
                            ui_msg(UiMsg::BadPsw(n.clone(), n));
                            self.failed_header_decryption = true;
                            set_error_code(RARX_BADPWD);
                            return 0;
                        } else {
                            ui_msg(UiMsg::WaitBadPsw(n.clone(), n));
                            self.cmd.borrow_mut().password_clean();
                            continue;
                        }
                    }
                }
                break;
            }
        }
        const FIRST_READ_SIZE: usize = 7;
        if self.raw_read(&mut raw, FIRST_READ_SIZE, decrypt) < FIRST_READ_SIZE {
            self.unexp_end_arc_msg();
            return 0;
        }
        let mut sb = BaseBlock { head_crc: raw.get4(), ..Default::default() };
        let size_bytes = raw.get_vsize(4);
        let block_size = raw.getv();
        if block_size == 0 || size_bytes == 0 {
            self.short_block = sb;
            self.broken_header_msg();
            return 0;
        }
        let size_to_read = block_size as i64 - (FIRST_READ_SIZE as i64 - size_bytes as i64 - 4);
        let header_size = 4 + size_bytes as u64 + block_size;
        if size_to_read < 0 || header_size < SIZEOF_SHORTBLOCKHEAD5 as u64 || block_size > MAX_HEADER_SIZE_RAR5 as u64 {
            self.short_block = sb;
            self.broken_header_msg();
            return 0;
        }
        self.raw_read(&mut raw, size_to_read as usize, decrypt);
        if (raw.size() as u64) < header_size {
            self.unexp_end_arc_msg();
            return 0;
        }
        let header_crc = raw.get_crc50();
        let ht = raw.getv();
        sb.header_type = ht.min(HEAD_UNKNOWN as u64) as u32;
        sb.flags = raw.getv() as u32;
        sb.skip_if_unknown = sb.flags & HFL_SKIPIFUNKNOWN != 0;
        sb.head_size = header_size as u32;
        self.cur_header_type = sb.header_type;
        self.short_block = sb.clone();

        let bad_crc = sb.head_crc != header_crc;
        if bad_crc {
            self.broken_header_msg();
            self.broken_header = true;
            set_error_code(RARX_CRC);
            if decrypt {
                let n = self.file_name().to_string();
                ui_msg(UiMsg::ChecksumEnc(n.clone(), n));
                self.failed_header_decryption = true;
                return 0;
            }
        }
        let mut extra_size: u64 = 0;
        if sb.flags & HFL_EXTRA != 0 {
            extra_size = raw.getv();
            if extra_size >= sb.head_size as u64 {
                self.broken_header_msg();
                return 0;
            }
        }
        let mut data_size: u64 = 0;
        if sb.flags & HFL_DATA != 0 {
            data_size = raw.getv();
        }
        self.next_block_pos = self.cur_block_pos + self.full_header_size(sb.head_size as usize) as i64;
        self.next_block_pos = safe_add(self.next_block_pos, data_size as i64, 0);

        match sb.header_type {
            HEAD_CRYPT => {
                let mut ch = CryptHeader { base: sb.clone(), ..Default::default() };
                let crypt_version = raw.getv() as u32 as u64;
                if crypt_version > CRYPT_VERSION {
                    let n = self.file_name().to_string();
                    self.unk_enc_ver_msg(&n, &format!("h{}", crypt_version));
                    self.failed_header_decryption = true;
                    return 0;
                }
                let enc_flags = raw.getv() as u32;
                ch.use_psw_check = enc_flags & CHFL_CRYPT_PSWCHECK != 0;
                ch.lg2_count = raw.get1() as u32;
                if ch.lg2_count > CRYPT5_KDF_LG2_COUNT_MAX {
                    let n = self.file_name().to_string();
                    self.unk_enc_ver_msg(&n, &format!("hc{}", ch.lg2_count));
                    self.failed_header_decryption = true;
                    return 0;
                }
                raw.getb(&mut ch.salt);
                if ch.use_psw_check {
                    raw.getb(&mut ch.psw_check);
                    let mut csum = [0u8; SIZE_PSWCHECK_CSUM];
                    raw.getb(&mut csum);
                    let digest = Sha256::digest(&ch.psw_check);
                    ch.use_psw_check = csum == digest[..SIZE_PSWCHECK_CSUM];
                }
                self.crypt_head = ch;
                self.encrypted = true;
            }
            HEAD_MAIN => {
                self.main_head = MainHeader { base: sb.clone(), ..Default::default() };
                let arc_flags = raw.getv() as u32;
                self.volume = arc_flags & MHFL_VOLUME != 0;
                self.solid = arc_flags & MHFL_SOLID != 0;
                self.locked = arc_flags & MHFL_LOCK != 0;
                self.protected = arc_flags & MHFL_PROTECT != 0;
                self.signed = false;
                self.new_numbering = true;
                self.vol_number = if arc_flags & MHFL_VOLNUMBER != 0 { raw.getv() as u32 } else { 0 };
                self.first_volume = self.volume && self.vol_number == 0;
                if extra_size != 0 {
                    self.process_extra50_main(&mut raw, extra_size as usize);
                }
                if !self.prohibit_qopen
                    && self.main_head.locator
                    && self.main_head.qopen_offset > 0
                    && self.cmd.borrow().qopen_mode != QOpenMode::None
                {
                    let save_cur = self.cur_block_pos;
                    let save_next = self.next_block_pos;
                    let save_type = self.cur_header_type;
                    self.qopen = QuickOpen::default();
                    let off = self.main_head.qopen_offset;
                    self.qo_load(off);
                    self.cur_block_pos = save_cur;
                    self.next_block_pos = save_next;
                    self.cur_header_type = save_type;
                }
            }
            HEAD_FILE | HEAD_SERVICE => {
                let file_block = sb.header_type == HEAD_FILE;
                let mut hd = if file_block { &self.file_head } else { &self.sub_head }.reset_copy(sb.clone());
                hd.large_file = true;
                hd.pack_size = data_size as i64;
                hd.file_flags = raw.getv() as u32;
                hd.unp_size = raw.getv() as i64;
                hd.unknown_unp_size = hd.file_flags & FHFL_UNPUNKNOWN != 0;
                if hd.unknown_unp_size {
                    hd.unp_size = INT64NDF;
                }
                hd.max_size = hd.pack_size.max(hd.unp_size);
                hd.file_attr = raw.getv() as u32;
                if hd.file_flags & FHFL_UTIME != 0 {
                    let t = raw.get4();
                    hd.mtime.set_unix(t as i64);
                }
                hd.file_hash.kind = HashType::None;
                if hd.file_flags & FHFL_CRC32 != 0 {
                    hd.file_hash.kind = HashType::Crc32;
                    hd.file_hash.crc32 = raw.get4();
                }
                hd.redir_type = FsRedir::None;
                let comp_info = raw.getv() as u32;
                hd.method = (comp_info >> 7) & 7;
                let unp_ver = comp_info & 0x3f;
                hd.unp_ver = match unp_ver {
                    0 => VER_PACK5,
                    1 => VER_PACK7,
                    _ => VER_UNKNOWN,
                };
                hd.host_os = raw.getv() as u8;
                let name_size = raw.getv() as usize;
                hd.inherited = sb.flags & HFL_INHERITED != 0;
                hd.hs_type = match hd.host_os {
                    HOST5_UNIX => HostSystemType::Unix,
                    HOST5_WINDOWS => HostSystemType::Windows,
                    _ => HostSystemType::Unknown,
                };
                hd.split_before = sb.flags & HFL_SPLITBEFORE != 0;
                hd.split_after = sb.flags & HFL_SPLITAFTER != 0;
                hd.sub_block = sb.flags & HFL_CHILD != 0;
                hd.solid = file_block && comp_info & FCI_SOLID != 0;
                hd.dir = hd.file_flags & FHFL_DIRECTORY != 0;
                if hd.dir || unp_ver > 1 {
                    hd.win_size = 0;
                } else {
                    hd.win_size = 0x20000u64 << ((comp_info >> 10) & if unp_ver == 0 { 0x0f } else { 0x1f });
                    if unp_ver == 1 {
                        hd.win_size += hd.win_size / 32 * ((comp_info >> 15) & 0x1f) as u64;
                        if comp_info & FCI_RAR5_COMPAT != 0 {
                            hd.unp_ver = VER_PACK5;
                        }
                        if hd.win_size > UNPACK_MAX_DICT {
                            hd.unp_ver = VER_UNKNOWN;
                        }
                    }
                }
                let read_name_size = name_size.min(MAXPATHSIZE);
                let name = raw.getb_vec(read_name_size);
                hd.file_name = utf_to_wide(&name);
                if extra_size != 0 {
                    self.process_extra50_file(&mut raw, extra_size as usize, &mut hd);
                }
                if file_block {
                    self.convert_name_case(&mut hd.file_name);
                    self.convert_file_header(&mut hd);
                }
                if !file_block && hd.cmp_name(SUBHEAD_TYPE_CMT) {
                    self.main_comment = true;
                }
                if !file_block && hd.cmp_name(SUBHEAD_TYPE_RR) && !hd.sub_data.is_empty() {
                    let mut rp = RawRead::new();
                    rp.read_mem(&hd.sub_data);
                    self.recovery_percent = rp.getv() as i32;
                }
                if bad_crc {
                    ui_msg(UiMsg::FHeaderBroken(self.file_name().to_string(), hd.file_name.clone()));
                }
                if file_block {
                    self.file_head = hd;
                } else {
                    self.sub_head = hd;
                }
            }
            HEAD_ENDARC => {
                let arc_flags = raw.getv() as u32;
                self.end_arc_head = EndArcHeader {
                    base: sb.clone(),
                    next_volume: arc_flags & EHFL_NEXTVOLUME != 0,
                    ..Default::default()
                };
            }
            _ => {}
        }
        raw.size()
    }

    /// Iterate over extra area records. Calls `f(raw, field_type, field_size, next_pos)`.
    fn for_each_extra(raw: &mut RawRead, extra_size: usize, mut f: impl FnMut(&mut RawRead, u64, i64, usize)) {
        let extra_start = raw.size().wrapping_sub(extra_size);
        if extra_start < raw.get_pos() || extra_start > raw.size() {
            return;
        }
        raw.set_pos(extra_start);
        while raw.data_left() >= 2 {
            let field_size = raw.getv() as i64;
            if field_size <= 0 || raw.data_left() == 0 || field_size > raw.data_left() as i64 {
                break;
            }
            let next_pos = raw.get_pos() + field_size as usize;
            let field_type = raw.getv();
            let field_size = next_pos as i64 - raw.get_pos() as i64;
            if field_size < 0 {
                break;
            }
            f(raw, field_type, field_size, next_pos);
            raw.set_pos(next_pos);
        }
    }

    fn process_extra50_main(&mut self, raw: &mut RawRead, extra_size: usize) {
        let cur_block_pos = self.cur_block_pos as u64;
        let hd = &mut self.main_head;
        Self::for_each_extra(raw, extra_size, |raw, field_type, _fs, _np| match field_type {
            MHEXTRA_LOCATOR => {
                hd.locator = true;
                let flags = raw.getv() as u32;
                if flags & MHEXTRA_LOCATOR_QLIST != 0 {
                    let off = raw.getv();
                    if off != 0 {
                        hd.qopen_offset = off.wrapping_add(cur_block_pos);
                    }
                }
                if flags & MHEXTRA_LOCATOR_RR != 0 {
                    let off = raw.getv();
                    if off != 0 {
                        hd.rr_offset = off.wrapping_add(cur_block_pos);
                    }
                }
            }
            MHEXTRA_METADATA => {
                let flags = raw.getv() as u32;
                if flags & MHEXTRA_METADATA_NAME != 0 {
                    let name_size = raw.getv();
                    if name_size > 0 && name_size < MAXPATHSIZE as u64 {
                        let n = raw.getb_vec(name_size as usize);
                        if n[0] != 0 {
                            hd.orig_name = utf_to_wide(&n);
                        }
                    }
                }
                if flags & MHEXTRA_METADATA_CTIME != 0 {
                    if flags & MHEXTRA_METADATA_UNIXTIME != 0 {
                        if flags & MHEXTRA_METADATA_UNIX_NS != 0 {
                            hd.orig_time.set_unix_ns(raw.get8());
                        } else {
                            hd.orig_time.set_unix(raw.get4() as i64);
                        }
                    } else {
                        hd.orig_time.set_win(raw.get8());
                    }
                }
            }
            _ => {}
        });
    }

    fn process_extra50_file(&mut self, raw: &mut RawRead, extra_size: usize, hd: &mut FileHeader) {
        let arc_name = self.file_name().to_string();
        let is_service = hd.base.header_type == HEAD_SERVICE;
        Self::for_each_extra(raw, extra_size, |raw, field_type, field_size, next_pos| match field_type {
            FHEXTRA_CRYPT => {
                let enc_version = raw.getv() as u32 as u64;
                if enc_version > CRYPT_VERSION {
                    ui_msg(UiMsg::UnknownEncMethod(arc_name.clone(), hd.file_name.clone(), format!("x{}", enc_version)));
                    set_error_code(RARX_FATAL);
                    hd.crypt_method = CryptMethod::Unknown;
                } else {
                    let flags = raw.getv() as u32;
                    hd.lg2_count = raw.get1() as u32;
                    if hd.lg2_count > CRYPT5_KDF_LG2_COUNT_MAX {
                        ui_msg(UiMsg::UnknownEncMethod(arc_name.clone(), hd.file_name.clone(), format!("xc{}", hd.lg2_count)));
                        set_error_code(RARX_FATAL);
                        hd.crypt_method = CryptMethod::Unknown;
                    } else {
                        hd.use_psw_check = flags & FHEXTRA_CRYPT_PSWCHECK != 0;
                        hd.use_hash_key = flags & FHEXTRA_CRYPT_HASHMAC != 0;
                        raw.getb(&mut hd.salt);
                        raw.getb(&mut hd.init_v);
                        if hd.use_psw_check {
                            raw.getb(&mut hd.psw_check);
                            let mut csum = [0u8; SIZE_PSWCHECK_CSUM];
                            raw.getb(&mut csum);
                            let digest = Sha256::digest(&hd.psw_check);
                            hd.use_psw_check = csum == digest[..SIZE_PSWCHECK_CSUM];
                            if is_service && hd.psw_check == [0u8; SIZE_PSWCHECK] {
                                hd.use_psw_check = false;
                            }
                        }
                        hd.salt_set = true;
                        hd.crypt_method = CryptMethod::Rar50;
                        hd.encrypted = true;
                    }
                }
            }
            FHEXTRA_HASH => {
                let t = raw.getv() as u32;
                if t == FHEXTRA_HASH_BLAKE2 {
                    hd.file_hash.kind = HashType::Blake2;
                    raw.getb(&mut hd.file_hash.digest);
                }
            }
            FHEXTRA_HTIME => {
                if field_size >= 5 {
                    let flags = raw.getv() as u8;
                    let unix_time = flags & FHEXTRA_HTIME_UNIXTIME != 0;
                    if flags & FHEXTRA_HTIME_MTIME != 0 {
                        if unix_time {
                            hd.mtime.set_unix(raw.get4() as i64);
                        } else {
                            hd.mtime.set_win(raw.get8());
                        }
                    }
                    if flags & FHEXTRA_HTIME_CTIME != 0 {
                        if unix_time {
                            hd.ctime.set_unix(raw.get4() as i64);
                        } else {
                            hd.ctime.set_win(raw.get8());
                        }
                    }
                    if flags & FHEXTRA_HTIME_ATIME != 0 {
                        if unix_time {
                            hd.atime.set_unix(raw.get4() as i64);
                        } else {
                            hd.atime.set_win(raw.get8());
                        }
                    }
                    if unix_time && flags & FHEXTRA_HTIME_UNIX_NS != 0 {
                        if flags & FHEXTRA_HTIME_MTIME != 0 {
                            let ns = raw.get4() & 0x3fffffff;
                            if ns < 1_000_000_000 {
                                hd.mtime.adjust(ns as i64);
                            }
                        }
                        if flags & FHEXTRA_HTIME_CTIME != 0 {
                            let ns = raw.get4() & 0x3fffffff;
                            if ns < 1_000_000_000 {
                                hd.ctime.adjust(ns as i64);
                            }
                        }
                        if flags & FHEXTRA_HTIME_ATIME != 0 {
                            let ns = raw.get4() & 0x3fffffff;
                            if ns < 1_000_000_000 {
                                hd.atime.adjust(ns as i64);
                            }
                        }
                    }
                }
            }
            FHEXTRA_VERSION => {
                if field_size >= 1 {
                    raw.getv();
                    let version = raw.getv() as u32;
                    if version != 0 {
                        hd.version = true;
                        hd.file_name.push_str(&format!(";{}", version));
                    }
                }
            }
            FHEXTRA_REDIR => {
                let redir_type = raw.getv();
                let flags = raw.getv() as u32;
                let name_size = raw.getv() as usize;
                if name_size > 0 && name_size < MAXPATHSIZE {
                    hd.redir_type = match redir_type {
                        0 => FsRedir::None,
                        1 => FsRedir::UnixSymlink,
                        2 => FsRedir::WinSymlink,
                        3 => FsRedir::Junction,
                        4 => FsRedir::Hardlink,
                        5 => FsRedir::FileCopy,
                        _ => FsRedir::Unknown,
                    };
                    hd.dir_target = flags & FHEXTRA_REDIR_DIR != 0;
                    let n = raw.getb_vec(name_size);
                    hd.redir_name = utf_to_wide(&n);
                    if !cfg!(unix) {
                        hd.redir_name = crate::pathfn::unix_slash_to_dos(&hd.redir_name);
                    }
                }
            }
            FHEXTRA_UOWNER => {
                let flags = raw.getv() as u32;
                hd.unix_owner_numeric = flags & FHEXTRA_UOWNER_NUMUID != 0;
                hd.unix_group_numeric = flags & FHEXTRA_UOWNER_NUMGID != 0;
                hd.unix_owner_name.clear();
                hd.unix_group_name.clear();
                if flags & FHEXTRA_UOWNER_UNAME != 0 {
                    let l = (raw.getv() as usize).min(255);
                    let mut v = raw.getb_vec(l);
                    if let Some(p) = v.iter().position(|&b| b == 0) {
                        v.truncate(p);
                    }
                    hd.unix_owner_name = v;
                }
                if flags & FHEXTRA_UOWNER_GNAME != 0 {
                    let l = (raw.getv() as usize).min(255);
                    let mut v = raw.getb_vec(l);
                    if let Some(p) = v.iter().position(|&b| b == 0) {
                        v.truncate(p);
                    }
                    hd.unix_group_name = v;
                }
                if hd.unix_owner_numeric {
                    hd.unix_owner_id = raw.getv() as u32;
                }
                if hd.unix_group_numeric {
                    hd.unix_group_id = raw.getv() as u32;
                }
                hd.unix_owner_set = true;
            }
            FHEXTRA_SUBDATA => {
                let mut fs = field_size;
                if is_service && raw.size() - next_pos == 1 {
                    fs += 1;
                }
                hd.sub_data = raw.getb_vec(fs as usize);
            }
            _ => {}
        });
    }

    fn read_header14(&mut self) -> usize {
        let mut raw = RawRead::new();
        if self.cur_block_pos <= self.sfx_size as i64 {
            self.raw_read(&mut raw, SIZEOF_MAINHEAD14, false);
            self.main_head = MainHeader::default();
            let mut mark = [0u8; 4];
            raw.getb(&mut mark);
            let head_size = raw.get2() as i64;
            if head_size < 7 {
                return 0;
            }
            let flags = raw.get1() as u32;
            self.next_block_pos = self.cur_block_pos + head_size;
            self.cur_header_type = HEAD_MAIN;
            self.volume = flags & MHD_VOLUME != 0;
            self.solid = flags & MHD_SOLID != 0;
            self.locked = flags & MHD_LOCK != 0;
            self.main_head.comment_in_header = flags & MHD_COMMENT != 0;
            self.main_head.pack_comment = flags & MHD_PACK_COMMENT != 0;
        } else {
            self.raw_read(&mut raw, SIZEOF_FILEHEAD14, false);
            let mut fh = self.file_head.reset_copy(BaseBlock::default());
            fh.base.header_type = HEAD_FILE;
            fh.data_size = raw.get4();
            fh.unp_size = raw.get4() as i64;
            fh.file_hash.kind = HashType::Rar14;
            fh.file_hash.crc32 = raw.get2() as u32;
            fh.base.head_size = raw.get2() as u32;
            if fh.base.head_size < 21 {
                return 0;
            }
            let file_time = raw.get4();
            fh.file_attr = raw.get1() as u32;
            fh.base.flags = raw.get1() as u32 | LONG_BLOCK;
            fh.unp_ver = if raw.get1() == 2 { 13 } else { 10 };
            let name_size = raw.get1() as usize;
            fh.method = raw.get1() as u32;
            fh.split_before = fh.base.flags & LHD_SPLIT_BEFORE != 0;
            fh.split_after = fh.base.flags & LHD_SPLIT_AFTER != 0;
            fh.encrypted = fh.base.flags & LHD_PASSWORD != 0;
            fh.crypt_method = if fh.encrypted { CryptMethod::Rar13 } else { CryptMethod::None };
            fh.pack_size = fh.data_size as i64;
            fh.win_size = 0x10000;
            fh.dir = fh.file_attr & 0x10 != 0;
            fh.host_os = HOST_MSDOS;
            fh.hs_type = HostSystemType::Windows;
            fh.mtime.set_dos(file_time);
            self.raw_read(&mut raw, name_size, false);
            let name = raw.getb_vec(name_size);
            fh.file_name = oem_to_wide(&name);
            self.convert_name_case(&mut fh.file_name);
            self.convert_file_header(&mut fh);
            if raw.size() != 0 {
                self.next_block_pos = self.cur_block_pos + fh.base.head_size as i64 + fh.pack_size;
            }
            self.cur_header_type = HEAD_FILE;
            self.file_head = fh;
        }
        if self.next_block_pos > self.cur_block_pos {
            raw.size()
        } else {
            0
        }
    }

    fn convert_name_case(&self, name: &mut String) {
        let c = self.cmd.borrow().convert_names;
        if c == NAMES_UPPERCASE {
            *name = wcsupper(name);
        }
        if c == NAMES_LOWERCASE {
            *name = wcslower(name);
        }
    }

    pub fn is_arc_dir(&self) -> bool {
        self.file_head.dir
    }

    /// Convert file attributes for the current platform.
    pub fn convert_attributes(&mut self) {
        let fh = &mut self.file_head;
        if cfg!(unix) {
            let mask = crate::extinfo::get_umask();
            match fh.hs_type {
                HostSystemType::Windows => {
                    if fh.file_attr & 0x10 != 0 {
                        fh.file_attr = 0o777 & !mask;
                    } else if fh.file_attr & 1 != 0 {
                        fh.file_attr = 0o444 & !mask;
                    } else {
                        fh.file_attr = 0o666 & !mask;
                    }
                }
                HostSystemType::Unix => {}
                HostSystemType::Unknown => {
                    fh.file_attr = if fh.dir { 0x41ff & !mask } else { 0x81b6 & !mask };
                }
            }
        } else if fh.hs_type != HostSystemType::Windows {
            fh.file_attr = if fh.dir { 0x10 } else { 0x20 };
        }
    }

    fn convert_file_header(&self, hd: &mut FileHeader) {
        let rar5 = self.format == RarFormat::Rar50;
        let mut out = String::with_capacity(hd.file_name.len());
        for c in hd.file_name.chars() {
            let mut c = c;
            if cfg!(unix) && c == '\\' && rar5 && hd.hs_type == HostSystemType::Windows {
                c = '_';
            }
            if !cfg!(unix) {
                if c == '\\' && rar5 {
                    c = '_';
                }
                if c == ':' {
                    c = '_';
                }
            }
            if c == '/' || c == '\\' && !rar5 {
                c = CPATHDIVIDER;
            }
            out.push(c);
        }
        if let Some(p) = out.find('\0') {
            out.truncate(p);
        }
        hd.file_name = out;
    }

    pub fn get_start_pos(&self) -> i64 {
        let mut start = (self.sfx_size + self.mark_head_size as usize) as i64;
        if self.format == RarFormat::Rar15 {
            start += self.main_head.base.head_size as i64;
        } else {
            start += self.crypt_head.base.head_size as i64 + self.full_header_size(self.main_head.base.head_size as usize) as i64;
        }
        start
    }

    /// Read data of current service header. If `dest` is None, data are
    /// returned in memory (or only tested if `want_data` is false).
    pub fn read_sub_data(&mut self, want_data: bool, dest: Option<&mut File>, test_mode: bool) -> (bool, Vec<u8>) {
        if self.broken_header {
            ui_msg(UiMsg::SubHeaderBroken(self.file_name().to_string()));
            set_error_code(RARX_CRC);
            return (false, Vec::new());
        }
        let max_ver = if self.format == RarFormat::Rar50 { VER_UNPACK7 } else { VER_UNPACK };
        if self.sub_head.method > 5 || self.sub_head.unp_ver > max_ver {
            ui_msg(UiMsg::SubHeaderUnknown(self.file_name().to_string()));
            return (false, Vec::new());
        }
        if self.sub_head.pack_size == 0 && !self.sub_head.split_after {
            return (true, Vec::new());
        }
        let mut io = ComprDataIO::new();
        let mut unp = Unpack::new();
        if unp.init(self.sub_head.win_size, false).is_err() {
            errhnd::bad_alloc();
        }
        let to_memory = dest.is_none();
        if to_memory {
            if self.sub_head.unp_size < 0 || self.sub_head.unp_size > 0x1000000 {
                ui_msg(UiMsg::SubHeaderUnknown(self.file_name().to_string()));
                return (false, Vec::new());
            }
            if !want_data {
                io.set_test_mode(true);
            } else {
                io.set_unpack_to_memory(self.sub_head.unp_size as usize);
            }
        }
        if self.sub_head.encrypted {
            if self.cmd.borrow().password_set() {
                let pwd = self.password();
                let sh = self.sub_head.clone();
                io.set_encryption(sh.crypt_method, &pwd, if sh.salt_set { Some(&sh.salt[..]) } else { None }, &sh.init_v, sh.lg2_count);
            } else {
                return (false, Vec::new());
            }
        }
        io.unp_hash.init(self.sub_head.file_hash.kind);
        io.set_packed_size_to_read(self.sub_head.pack_size);
        io.enable_show_progress(false);
        io.set_test_mode(test_mode || to_memory && !want_data);
        io.unp_volume = self.sub_head.split_after;
        io.set_sub_header(true);
        unp.set_dest_size(self.sub_head.unp_size);
        let method = self.sub_head.method;
        let unp_ver = self.sub_head.unp_ver;
        let unp_size = self.sub_head.unp_size;
        {
            let mut ctx = DataIoCtx { io: &mut io, arc: self, dest };
            if method == 0 {
                crate::extract::unstore_file(&mut ctx, unp_size);
            } else {
                unp.do_unpack(unp_ver, false, &mut ctx);
            }
        }
        let key = if self.sub_head.use_hash_key { Some(&self.sub_head.hash_key) } else { None };
        if !io.unp_hash.cmp(&self.sub_head.file_hash, key) {
            ui_msg(UiMsg::SubHeaderDataBroken(self.file_name().to_string(), self.sub_head.file_name.clone()));
            set_error_code(RARX_CRC);
            return (false, Vec::new());
        }
        (true, io.take_memory())
    }

    /// Unpack RAR 2.x NTFS security or stream subblock data following its
    /// header. Returns unpacked data if `dest` is None and data CRC32.
    pub fn unpack_old_sub(&mut self, pack_size: u32, unp_size: u32, unp_ver: u8, dest: Option<&mut File>) -> (Vec<u8>, u32) {
        let mut io = ComprDataIO::new();
        let mut unp = Unpack::new();
        if unp.init(0x10000, false).is_err() {
            errhnd::bad_alloc();
        }
        if dest.is_none() {
            io.set_unpack_to_memory(unp_size as usize);
        }
        io.set_packed_size_to_read(pack_size as i64);
        io.enable_show_progress(false);
        io.unp_hash.init(HashType::Crc32);
        unp.set_dest_size(unp_size as i64);
        {
            let mut ctx = DataIoCtx { io: &mut io, arc: self, dest };
            unp.do_unpack(unp_ver as u32, false, &mut ctx);
        }
        let crc = io.unp_hash.crc32();
        (io.take_memory(), crc)
    }

    pub fn get_comment(&mut self) -> Option<String> {
        if !self.main_comment {
            return None;
        }
        let save = self.tell();
        let r = self.do_get_comment();
        self.seek(save, SEEK_SET);
        r
    }

    fn do_get_comment(&mut self) -> Option<String> {
        let mut cmt_length: usize;
        if self.format == RarFormat::Rar14 {
            let p = (self.sfx_size + SIZEOF_MAINHEAD14) as i64;
            self.seek(p, SEEK_SET);
            cmt_length = self.get_byte() as usize;
            cmt_length += (self.get_byte() as usize) << 8;
        } else {
            if self.main_head.comment_in_header {
                let p = (self.sfx_size + SIZEOF_MARKHEAD3 + SIZEOF_MAINHEAD3) as i64;
                self.seek(p, SEEK_SET);
                if self.read_header() == 0 || self.get_header_type() != HEAD3_CMT {
                    return None;
                }
            } else {
                let p = self.get_start_pos();
                self.seek(p, SEEK_SET);
                if self.search_sub_block(SUBHEAD_TYPE_CMT) != 0 {
                    match self.read_comment_data() {
                        Some(c) => return Some(c),
                        None => ui_msg(UiMsg::CmtBroken(self.file_name().to_string())),
                    }
                }
                return None;
            }
            if self.broken_header || (self.comm_head.base.head_size as usize) < SIZEOF_COMMHEAD {
                ui_msg(UiMsg::CmtBroken(self.file_name().to_string()));
                return None;
            }
            cmt_length = self.comm_head.base.head_size as usize - SIZEOF_COMMHEAD;
        }
        
        let cmt_data = if self.format == RarFormat::Rar14 && self.main_head.pack_comment || self.format != RarFormat::Rar14 && self.comm_head.method != 0x30 {
            if self.format != RarFormat::Rar14
                && (self.comm_head.unp_ver < 15 || self.comm_head.unp_ver as u32 > VER_UNPACK || self.comm_head.method > 0x35)
            {
                return None;
            }
            let mut io = ComprDataIO::new();
            io.set_test_mode(true);
            let unp_cmt_length;
            if self.format == RarFormat::Rar14 {
                unp_cmt_length = self.get_byte() as usize + ((self.get_byte() as usize) << 8);
                if cmt_length < 2 {
                    return None;
                }
                cmt_length -= 2;
                io.set_cmt13_encryption();
                self.comm_head.unp_ver = 15;
            } else {
                unp_cmt_length = self.comm_head.unp_size as usize;
            }
            io.enable_show_progress(false);
            io.set_packed_size_to_read(cmt_length as i64);
            io.unp_hash.init(HashType::Crc32);
            io.set_no_file_header(true);
            io.keep_last_write(true);
            let mut unp = Unpack::new();
            let _ = unp.init(0x10000, false);
            unp.set_dest_size(unp_cmt_length as i64);
            let ver = self.comm_head.unp_ver as u32;
            {
                let mut ctx = DataIoCtx { io: &mut io, arc: self, dest: None };
                unp.do_unpack(ver, false, &mut ctx);
            }
            if self.format != RarFormat::Rar14 && (io.unp_hash.crc32() & 0xffff) != self.comm_head.comm_crc as u32 {
                ui_msg(UiMsg::CmtBroken(self.file_name().to_string()));
                return None;
            }
            let data = io.last_write();
            oem_to_wide(&data)
        } else {
            if cmt_length == 0 {
                return None;
            }
            let mut raw = vec![0u8; cmt_length];
            let r = self.read(&mut raw);
            if r >= 0 && (r as usize) < cmt_length {
                raw.truncate(r as usize);
            }
            if self.format != RarFormat::Rar14 && self.comm_head.comm_crc as u32 != (!crate::hash::crc32::crc32(0xffffffff, &raw) & 0xffff) {
                ui_msg(UiMsg::CmtBroken(self.file_name().to_string()));
                return None;
            }
            oem_to_wide(&raw)
        };
        if cmt_data.is_empty() {
            None
        } else {
            Some(cmt_data)
        }
    }

    fn read_comment_data(&mut self) -> Option<String> {
        let (ok, raw) = self.read_sub_data(true, None, false);
        if !ok {
            return None;
        }
        Some(if self.format == RarFormat::Rar50 {
            utf_to_wide(&raw)
        } else if self.sub_head.sub_flags() & SUBHEAD_FLAGS_CMT_UNICODE != 0 {
            crate::unicode::raw_to_wide(&raw)
        } else {
            char_to_wide(&raw)
        })
    }

    pub fn view_comment(&mut self) {
        if self.cmd.borrow().disable_comment {
            return;
        }
        if let Some(c) = self.get_comment() {
            crate::consio::mprintf(crate::loclang::MArcComment);
            crate::consio::mprintf(":\n");
            crate::consio::out_comment(&c);
        }
    }

    // Quick open implementation.

    fn qo_load(&mut self, block_pos: u64) {
        if !self.qopen.loaded {
            self.qopen.seek_pos = self.tell() as u64;
            self.qopen.unsync_seek_pos = false;
            let save_pos = self.qopen.seek_pos as i64;
            self.seek(block_pos as i64, SEEK_SET);
            self.prohibit_qopen = true;
            let read_size = self.read_header();
            self.prohibit_qopen = false;
            if read_size == 0 || self.get_header_type() != HEAD_SERVICE || !self.sub_head.cmp_name(SUBHEAD_TYPE_QOPEN) {
                self.seek(save_pos, SEEK_SET);
                return;
            }
            self.qopen.qo_header_pos = self.cur_block_pos as u64;
            self.qopen.raw_data_start = self.tell() as u64;
            self.qopen.raw_data_size = self.sub_head.unp_size as u64;
            self.seek(save_pos, SEEK_SET);
            self.qopen.loaded = true;
        }
        self.qopen.encrypted = self.sub_head.encrypted;
        if self.sub_head.encrypted {
            if self.cmd.borrow().password_set() {
                let pwd = self.password();
                let sh = self.sub_head.clone();
                self.qopen.crypt.set_keys(CryptMethod::Rar50, &pwd, Some(&sh.salt), Some(&sh.init_v), sh.lg2_count);
            } else {
                self.qopen.loaded = false;
                return;
            }
        }
        self.qopen.raw_data_pos = 0;
        self.qopen.read_buf_size = 0;
        self.qopen.read_buf_pos = 0;
        self.qopen.last_read_header.clear();
        self.qopen.last_read_header_pos = 0;
        if self.qopen.buf.len() != QO_MAX_BUF_SIZE {
            self.qopen.buf = vec![0; QO_MAX_BUF_SIZE];
        }
        self.qo_read_buffer();
    }

    fn qo_read(&mut self, data: &mut [u8]) -> Option<usize> {
        if !self.qopen.loaded {
            return None;
        }
        while self.qopen.last_read_header_pos + self.qopen.last_read_header.len() as u64 <= self.qopen.seek_pos {
            if !self.qo_read_next() {
                break;
            }
        }
        if !self.qopen.loaded {
            if self.qopen.unsync_seek_pos {
                let p = self.qopen.seek_pos as i64;
                self.file.seek(p, SEEK_SET);
            }
            return None;
        }
        let q = &self.qopen;
        let size = data.len() as u64;
        if q.seek_pos >= q.last_read_header_pos && q.seek_pos + size <= q.last_read_header_pos + q.last_read_header.len() as u64 {
            let off = (q.seek_pos - q.last_read_header_pos) as usize;
            data.copy_from_slice(&q.last_read_header[off..off + data.len()]);
            self.qopen.seek_pos += size;
            self.qopen.unsync_seek_pos = true;
            Some(data.len())
        } else {
            if self.qopen.unsync_seek_pos {
                let p = self.qopen.seek_pos as i64;
                self.file.seek(p, SEEK_SET);
                self.qopen.unsync_seek_pos = false;
            }
            let r = self.file.read(data);
            if r < 0 {
                self.qopen.loaded = false;
                return None;
            }
            self.qopen.seek_pos += r as u64;
            Some(r as usize)
        }
    }

    fn qo_seek(&mut self, offset: i64, method: i32) -> bool {
        if !self.qopen.loaded {
            return false;
        }
        if method == SEEK_SET && (offset as u64) < self.qopen.seek_pos && (offset as u64) < self.qopen.last_read_header_pos {
            let p = self.qopen.qo_header_pos;
            self.qo_load(p);
        }
        if method == SEEK_SET {
            self.qopen.seek_pos = offset as u64;
        }
        if method == crate::file::SEEK_CUR {
            self.qopen.seek_pos = self.qopen.seek_pos.wrapping_add(offset as u64);
        }
        self.qopen.unsync_seek_pos = true;
        if method == SEEK_END {
            self.file.seek(offset, SEEK_END);
            self.qopen.seek_pos = self.file.tell() as u64;
            self.qopen.unsync_seek_pos = false;
        }
        true
    }

    fn qo_read_buffer(&mut self) -> usize {
        let save_pos = self.tell();
        let p = (self.qopen.raw_data_start + self.qopen.raw_data_pos) as i64;
        self.file.seek(p, SEEK_SET);
        let q = &mut self.qopen;
        let mut size_to_read = (q.raw_data_size - q.raw_data_pos).min((QO_MAX_BUF_SIZE - q.read_buf_size) as u64) as usize;
        if q.encrypted {
            size_to_read &= !CRYPT_BLOCK_MASK;
        }
        let mut read_size = 0;
        if size_to_read != 0 {
            let start = q.read_buf_size;
            let r = self.file.read(&mut self.qopen.buf[start..start + size_to_read]);
            if r > 0 {
                read_size = r as usize;
                let q = &mut self.qopen;
                if q.encrypted {
                    let n = read_size & !CRYPT_BLOCK_MASK;
                    q.crypt.decrypt(&mut q.buf[start..start + n]);
                }
                q.raw_data_pos += read_size as u64;
                q.read_buf_size += read_size;
            }
        }
        self.seek(save_pos, SEEK_SET);
        read_size
    }

    fn qo_read_raw(&mut self, raw: &mut RawRead) -> bool {
        if QO_MAX_BUF_SIZE - self.qopen.read_buf_pos < 0x100 {
            let q = &mut self.qopen;
            let left = q.read_buf_size - q.read_buf_pos;
            q.buf.copy_within(q.read_buf_pos..q.read_buf_pos + left, 0);
            q.read_buf_pos = 0;
            q.read_buf_size = left;
            self.qo_read_buffer();
        }
        const FIRST: usize = 7;
        let q = &mut self.qopen;
        if q.read_buf_pos + FIRST > q.read_buf_size {
            return false;
        }
        raw.read_mem(&q.buf[q.read_buf_pos..q.read_buf_pos + FIRST]);
        q.read_buf_pos += FIRST;
        let saved_crc = raw.get4();
        let size_bytes = raw.get_vsize(4);
        let block_size = raw.getv();
        let mut size_to_read = block_size as i64 - (FIRST as i64 - size_bytes as i64 - 4);
        if size_to_read < 0 || size_bytes == 0 || block_size == 0 {
            self.qopen.loaded = false;
            return false;
        }
        while size_to_read > 0 {
            let q = &mut self.qopen;
            let left = q.read_buf_size - q.read_buf_pos;
            let cur = left.min(size_to_read as usize);
            raw.read_mem(&q.buf[q.read_buf_pos..q.read_buf_pos + cur]);
            q.read_buf_pos += cur;
            size_to_read -= cur as i64;
            if size_to_read > 0 {
                q.read_buf_pos = 0;
                q.read_buf_size = 0;
                if self.qo_read_buffer() == 0 {
                    return false;
                }
            }
        }
        saved_crc == raw.get_crc50()
    }

    fn qo_read_next(&mut self) -> bool {
        let mut raw = RawRead::new();
        if !self.qo_read_raw(&mut raw) {
            return false;
        }
        let _flags = raw.getv();
        let offset = raw.getv();
        let header_size = raw.getv() as usize;
        if header_size > MAX_HEADER_SIZE_RAR5 {
            return false;
        }
        self.qopen.last_read_header = raw.getb_vec(header_size);
        self.qopen.last_read_header_pos = self.qopen.qo_header_pos.wrapping_sub(offset);
        true
    }
}
