// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Extract, test and print commands.

use crate::archive::{Archive, RarFormat};
use crate::cmddata::{AppendArcName, CmdRef, ExtTimeMode, PathExclMode};
use crate::consio::{ask, eprintf, mprintf};
use crate::crypt::CryptMethod;
use crate::errhnd::{self, *};
use crate::extinfo::*;
use crate::file::{File, SEEK_SET};
use crate::filcreat::{file_create, FILECR_DEFAULT, FILECR_FOLDER, FILECR_WRITEONLY};
use crate::filefn::*;
use crate::find::{fast_find, FindData};
use crate::hash::HashType;
use crate::headers::*;
use crate::loclang::*;
use crate::matchfn::MATCH_WILDSUBPATH;
use crate::pathfn::*;
use crate::rdwrfn::{ComprDataIO, DataIoCtx};
use crate::strfn::{toupperw, wcsicomp_eq, wcsnicompc_eq};
use crate::timefn::RarTime;
use crate::ui::*;
use crate::unpack::{Unpack, UnpackIo};
use crate::wfmt;

#[derive(PartialEq, Eq)]
enum ExtractArcCode {
    Next,
    Repeat,
}

struct ExtractRef {
    ref_name: String,
    tmp_name: String,
    ref_count: u64,
}

#[derive(Default)]
struct AnalyzeData {
    start_name: String,
    start_pos: u64,
    end_name: String,
    end_pos: u64,
}

pub struct CmdExtract {
    cmd: CmdRef,
    data_io: ComprDataIO,
    unp: Unpack,
    ref_list: Vec<ExtractRef>,
    analyze: AnalyzeData,
    arc_analyzed: bool,
    start_time: RarTime,
    total_file_count: u64,
    file_count: u64,
    matched_args: u64,
    first_file: bool,
    all_matches_exact: bool,
    reconstruct_done: bool,
    use_exact_vol_name: bool,
    any_solid_data_unpacked_well: bool,
    arc_name: String,
    global_password: bool,
    prev_processed: bool,
    dest_file_name: String,
    suppress_no_files_message: bool,
    convert_symlink_paths: bool,
    last_checked_symlink: String,
}

/// Copy stored (not compressed) data.
pub fn unstore_file(io: &mut dyn UnpackIo, dest_unp_size: i64) {
    let mut buf = vec![0u8; 0x400000];
    let mut left = dest_unp_size;
    loop {
        let r = io.unp_read(&mut buf);
        if r <= 0 {
            break;
        }
        let w = if (r as i64) < left { r as i64 } else { left };
        if w > 0 {
            io.unp_write(&buf[..w as usize]);
            left -= w;
        }
    }
}

impl CmdExtract {
    pub fn new(cmd: CmdRef) -> Self {
        let mut unp = Unpack::new();
        unp.set_threads(cmd.borrow().threads);
        CmdExtract {
            cmd,
            data_io: ComprDataIO::new(),
            unp,
            ref_list: Vec::new(),
            analyze: AnalyzeData::default(),
            arc_analyzed: false,
            start_time: RarTime::default(),
            total_file_count: 0,
            file_count: 0,
            matched_args: 0,
            first_file: true,
            all_matches_exact: true,
            reconstruct_done: false,
            use_exact_vol_name: false,
            any_solid_data_unpacked_well: false,
            arc_name: String::new(),
            global_password: false,
            prev_processed: false,
            dest_file_name: String::new(),
            suppress_no_files_message: false,
            convert_symlink_paths: true,
            last_checked_symlink: String::new(),
        }
    }

    fn free_analyze_data(&mut self) {
        for r in &self.ref_list {
            if !r.tmp_name.is_empty() {
                del_file(&r.tmp_name);
            }
        }
        self.ref_list.clear();
        self.analyze = AnalyzeData::default();
    }

    pub fn do_extract(&mut self) {
        self.suppress_no_files_message = false;
        let c0 = self.cmd.borrow().cmd_char();
        self.data_io.set_current_command(c0);
        if self.cmd.borrow().use_stdin.is_empty() {
            loop {
                let n = self.cmd.borrow_mut().get_arc_name();
                match n {
                    Some(n) => {
                        self.arc_name = n;
                        let mut fd = FindData::default();
                        if fast_find(&self.arc_name, &mut fd, false) {
                            self.data_io.total_arc_size += fd.size as i64;
                        }
                    }
                    None => break,
                }
            }
        }
        self.cmd.borrow_mut().arc_names.rewind();
        let mut arc_count = 0;
        loop {
            let n = self.cmd.borrow_mut().get_arc_name();
            match n {
                Some(n) => self.arc_name = n,
                None => break,
            }
            {
                let mut c = self.cmd.borrow_mut();
                if c.manual_password {
                    c.password_clean();
                }
            }
            self.reconstruct_done = false;
            self.use_exact_vol_name = false;
            loop {
                if arc_count > 0 {
                    mprintf("\n");
                }
                if self.extract_archive() != ExtractArcCode::Repeat {
                    break;
                }
            }
            self.data_io.processed_arc_size += self.data_io.last_arc_size;
            arc_count += 1;
        }
        {
            let mut c = self.cmd.borrow_mut();
            if c.manual_password {
                c.password_clean();
            }
        }
        if self.total_file_count == 0 && c0 != 'I' && get_error_code() != RARX_BADPWD {
            if !self.suppress_no_files_message {
                ui_msg(UiMsg::NoFilesToExtract(self.arc_name.clone()));
            }
            if get_error_code() == RARX_SUCCESS {
                set_error_code(RARX_NOFILES);
            }
        } else if !self.cmd.borrow().disable_done {
            if c0 == 'I' {
                mprintf(MDone);
            } else if get_error_count() == 0 {
                mprintf(MExtrAllOk);
            } else {
                mprintf(&wfmt!(MExtrTotalErr, get_error_count()));
            }
        }
        self.free_analyze_data();
    }

    fn extract_archive_init(&mut self, arc: &mut Archive) {
        {
            let mut c = self.cmd.borrow_mut();
            let c0 = c.cmd_char();
            if c0 == 'T' || c0 == 'I' {
                c.test = true;
            }
        }
        {
            let c = self.cmd.borrow();
            if cfg!(windows) && !c.test && c.motw_list.items_count() > 0 {
                let n = arc.file_name().to_string();
                arc.motw.read_zone_id_stream(&n, c.motw_all_fields);
            }
        }
        self.data_io.adjust_total_arc_size(arc);
        self.file_count = 0;
        self.matched_args = 0;
        self.first_file = true;
        self.global_password = self.cmd.borrow().password_set();
        self.data_io.unp_volume = false;
        self.prev_processed = false;
        self.all_matches_exact = true;
        self.any_solid_data_unpacked_well = false;
        self.arc_analyzed = false;
        self.start_time.set_current_time();
        self.last_checked_symlink.clear();
    }

    fn extract_archive(&mut self) -> ExtractArcCode {
        let mut arc = Archive::new(self.cmd.clone());
        let use_stdin = !self.cmd.borrow().use_stdin.is_empty();
        if use_stdin {
            arc.file.set_handle_std();
            arc.set_prohibit_qopen(true);
        } else if !arc.w_open(&self.arc_name.clone()) {
            return ExtractArcCode::Next;
        }
        if !arc.is_archive(true) {
            if cmp_ext(&self.arc_name, "rev") {
                let (first, _) = vol_name_to_first_name(&self.arc_name, true);
                if !wcsicomp_eq(&self.arc_name, &first) && file_exist(&first) && self.cmd.borrow().arc_names.search(&first, false) {
                    return ExtractArcCode::Next;
                }
                crate::recvol::rec_volumes_test(&self.cmd, None, &self.arc_name.clone());
                self.total_file_count += 1;
                return ExtractArcCode::Next;
            }
            let rar_ext = cmp_ext(&self.arc_name, "rar");
            if rar_ext {
                ui_msg(UiMsg::BadArchive(self.arc_name.clone()));
            } else {
                mprintf(&wfmt!(MNotRAR, self.arc_name.as_str()));
            }
            if rar_ext {
                set_error_code(RARX_BADARC);
            }
            return ExtractArcCode::Next;
        }
        if arc.failed_header_decryption {
            return ExtractArcCode::Next;
        }
        let first_volume = arc.first_volume;
        if arc.volume && !arc.first_volume && !self.use_exact_vol_name {
            let (first, _) = vol_name_to_first_name(&self.arc_name, arc.new_numbering);
            if !wcsicomp_eq(&self.arc_name, &first) && file_exist(&first) && self.cmd.borrow().arc_names.search(&first, false) {
                return ExtractArcCode::Next;
            }
        }
        arc.view_comment();
        let mut volume_set_size: i64 = 0;
        if !self.arc_analyzed && !use_stdin {
            let name = arc.file_name().to_string();
            self.analyze_archive(&name, arc.volume, arc.new_numbering);
            self.arc_analyzed = true;
        }
        if arc.volume {
            if !self.analyze.start_name.is_empty() {
                self.arc_name = std::mem::take(&mut self.analyze.start_name);
                self.use_exact_vol_name = true;
                return ExtractArcCode::Repeat;
            }
            let mut next = arc.file_name().to_string();
            loop {
                next_volume_name(&mut next, !arc.new_numbering);
                let mut fd = FindData::default();
                if fast_find(&next, &mut fd, false) {
                    volume_set_size += fd.size as i64;
                } else {
                    break;
                }
            }
            self.data_io.total_arc_size += volume_set_size;
        }
        self.extract_archive_init(&mut arc);
        let c0 = self.cmd.borrow().cmd_char();
        if c0 == 'I' {
            self.cmd.borrow_mut().disable_percentage = true;
        } else {
            let test = self.cmd.borrow().test;
            ui_start_archive_extract(!test, &self.arc_name);
        }
        if self.analyze.start_pos != 0 {
            arc.seek(self.analyze.start_pos as i64, SEEK_SET);
            self.analyze.start_pos = 0;
        }
        loop {
            let size = arc.read_header();
            let mut repeat = false;
            if !self.extract_current_file(&mut arc, size, &mut repeat) {
                if repeat {
                    let mut fd = FindData::default();
                    if fast_find(&self.arc_name, &mut fd, false) {
                        self.data_io.total_arc_size = fd.size as i64;
                    }
                    return ExtractArcCode::Repeat;
                }
                break;
            }
        }
        let (test, del_arc) = {
            let c = self.cmd.borrow();
            (c.test, c.delete_archive)
        };
        if test && arc.volume {
            let n = self.arc_name.clone();
            crate::recvol::rec_volumes_test(&self.cmd, Some(&mut arc), &n);
        }
        if del_arc && !test && c0 != 'P' && get_error_code() == RARX_SUCCESS && (!arc.volume || first_volume) {
            let n = self.arc_name.clone();
            self.delete_archive(&mut arc, &n);
        }
        ExtractArcCode::Next
    }

    fn delete_archive(&mut self, arc: &mut Archive, arc_name: &str) {
        arc.close();
        let mut del_success;
        let mut next = arc_name.to_string();
        loop {
            del_success = del_file(&next);
            ui_msg(UiMsg::DelAddedFile(next.clone(), del_success));
            if !del_success || !arc.volume {
                break;
            }
            next_volume_name(&mut next, !arc.new_numbering);
            if !file_exist(&next) {
                break;
            }
        }
        if del_success && arc.volume {
            let mut next = arc_name.to_string();
            set_ext(&mut next, "rev");
            while file_exist(&next) {
                del_success = del_file(&next);
                ui_msg(UiMsg::DelAddedFile(next.clone(), del_success));
                if !del_success {
                    break;
                }
                next_volume_name(&mut next, !arc.new_numbering);
            }
        }
        if !del_success {
            set_error_code(RARX_DELETE);
        }
    }

    fn extract_current_file(&mut self, arc: &mut Archive, header_size: usize, repeat: &mut bool) -> bool {
        let command = self.cmd.borrow().cmd_char();
        if header_size == 0 {
            if self.data_io.unp_volume {
                if !crate::volume::merge_archive(arc, Some(&mut self.data_io), false, command) {
                    set_error_code(RARX_WARNING);
                    return false;
                }
            } else {
                return false;
            }
        }
        let header_type = arc.get_header_type();
        if header_type == HEAD_FILE {
            if self.analyze.end_pos != 0
                && self.analyze.end_pos as i64 == arc.cur_block_pos
                && (self.analyze.end_name.is_empty() || self.analyze.end_name == arc.file_name())
            {
                return false;
            }
        } else {
            if arc.format == RarFormat::Rar15 && header_type == HEAD3_OLDSERVICE && self.prev_processed {
                let c = self.cmd.borrow().clone();
                let d = self.dest_file_name.clone();
                crate::extinfo::set_extra_info20(&c, arc, &d);
            }
            if header_type == HEAD_SERVICE && self.prev_processed {
                let c = self.cmd.borrow().clone();
                let d = self.dest_file_name.clone();
                set_extra_info(&c, arc, &d);
            }
            if header_type == HEAD_ENDARC {
                if arc.end_arc_head.next_volume {
                    if !crate::volume::merge_archive(arc, Some(&mut self.data_io), false, command) {
                        set_error_code(RARX_WARNING);
                        return false;
                    }
                    let p = arc.cur_block_pos;
                    arc.seek(p, SEEK_SET);
                    return true;
                }
                return false;
            }
            arc.seek_to_next();
            return true;
        }
        self.prev_processed = false;
        if arc.file_head.pack_size < 0 {
            arc.file_head.pack_size = 0;
        }
        if arc.file_head.unp_size < 0 {
            arc.file_head.unp_size = 0;
        }
        {
            let c = self.cmd.borrow();
            if c.recurse == crate::cmddata::RecurseMode::None
                && self.matched_args >= c.file_args.items_count() as u64
                && self.all_matches_exact
            {
                return false;
            }
        }
        let mut equal_names = false;
        let mut matched_arg = String::new();
        let mut match_found =
            self.cmd.borrow().is_process_file(&arc.file_head, Some(&mut equal_names), MATCH_WILDSUBPATH, Some(&mut matched_arg)) != 0;
        if self.cmd.borrow().excl_path == PathExclMode::BasePath {
            let mut ap = get_path_with_sep(&matched_arg);
            if is_wildcard(&ap) {
                ap.clear();
            }
            self.cmd.borrow_mut().arc_path = ap;
        }
        if match_found && !equal_names {
            self.all_matches_exact = false;
        }
        arc.convert_attributes();

        if arc.file_head.split_before && self.first_file && !self.use_exact_vol_name {
            let start = self.get_first_vol_if_full_set(&self.arc_name.clone(), arc.new_numbering);
            if start != self.arc_name && file_exist(&start) {
                self.arc_name = start.clone();
                self.cmd.borrow_mut().arc_name = start;
                *repeat = true;
                return false;
            }
            if !self.reconstruct_done {
                self.reconstruct_done = true;
                let n = arc.file_name().to_string();
                if crate::recvol::rec_volumes_restore(&self.cmd, &n, true) {
                    *repeat = true;
                    return false;
                }
            }
        }

        let (_, mut arc_file_name) = convert_path(&arc.file_head.file_name);
        let version_control = self.cmd.borrow().version_control;
        if arc.file_head.version {
            if version_control != 1 && !equal_names {
                if version_control == 0 {
                    match_found = false;
                }
                let version = parse_version_file_name(&mut arc_file_name, false);
                if version_control as i32 - 1 == version {
                    parse_version_file_name(&mut arc_file_name, true);
                } else {
                    match_found = false;
                }
            }
        } else if !arc.is_arc_dir() && version_control > 1 {
            match_found = false;
        }

        self.data_io.unp_volume = arc.file_head.split_after;
        self.data_io.next_volume_missing = false;
        let p = arc.next_block_pos - arc.file_head.pack_size;
        arc.seek(p, SEEK_SET);

        let mut extr_file = false;
        let mut skip_solid = false;

        if self.first_file && (match_found || arc.solid) && arc.file_head.split_before {
            if match_found {
                ui_msg(UiMsg::NeedPrevVol(arc.file_name().to_string(), arc_file_name.clone()));
                set_error_code(RARX_OPEN);
            }
            match_found = false;
        }
        self.first_file = false;

        let test = self.cmd.borrow().test;
        let mut ref_target = false;
        if !match_found {
            for i in 0..self.ref_list.len() {
                if arc_file_name == self.ref_list[i].ref_name {
                    if !test {
                        let c = self.cmd.borrow();
                        self.dest_file_name = if !c.temp_path.is_empty() { c.temp_path.clone() } else { c.extr_path.clone() };
                        drop(c);
                        add_end_slash(&mut self.dest_file_name);
                        self.dest_file_name.push_str("__tmp_reference_source_");
                        mk_temp(&mut self.dest_file_name, None);
                        self.ref_list[i].tmp_name = self.dest_file_name.clone();
                    }
                    ref_target = true;
                    break;
                }
            }
        }

        if arc.file_head.encrypted && self.cmd.borrow().skip_encrypted {
            if arc.solid {
                return false;
            } else {
                match_found = false;
            }
        }

        skip_solid = arc.solid && !(match_found || ref_target) || skip_solid;
        if match_found || ref_target || arc.solid {
            if !ref_target {
                let mut d = String::new();
                self.extr_prepare_name(arc, &arc_file_name, &mut d);
                self.dest_file_name = d;
            }
            extr_file = !skip_solid && !arc_file_name.is_empty() && !self.dest_file_name.is_empty() && !arc.file_head.split_before;

            let (fresh, update) = {
                let c = self.cmd.borrow();
                (c.fresh_files, c.update_files)
            };
            if (fresh || update) && (command == 'E' || command == 'X') {
                let mut fd = FindData::default();
                if fast_find(&self.dest_file_name, &mut fd, false) {
                    if fd.mtime >= arc.file_head.mtime && (!fd.is_dir || fd.mtime < self.start_time) {
                        extr_file = false;
                    }
                } else if fresh {
                    extr_file = false;
                }
            }

            if !self.check_unp_ver(arc, &arc_file_name) {
                set_error_code(RARX_FATAL);
                arc.seek_to_next();
                return !arc.solid;
            }

            if arc.file_head.encrypted {
                loop {
                    if !self.extr_get_password(arc, &arc_file_name) {
                        self.suppress_no_files_message = true;
                        return false;
                    }
                    let mut pwd = self.cmd.borrow().password.clone().unwrap_or_default();
                    let fh = arc.file_head.clone();
                    if cfg!(windows) && arc.format == RarFormat::Rar15 && fh.host_os == HOST_MSDOS {
                        // Files encrypted by RAR for DOS use OEM password.
                        pwd = crate::unicode::char_to_wide(&crate::unicode::wide_to_oem(&pwd));
                    }
                    let keys = self.data_io.set_encryption(
                        fh.crypt_method,
                        &pwd,
                        if fh.salt_set { Some(&fh.salt[..]) } else { None },
                        &fh.init_v,
                        fh.lg2_count,
                    );
                    if let Some(k) = &keys {
                        if fh.crypt_method == CryptMethod::Rar50 {
                            arc.file_head.hash_key = k.hash_key;
                        }
                    }
                    if let Some(k) = keys {
                        if fh.use_psw_check && !arc.broken_header && fh.psw_check != k.psw_check {
                            if self.global_password {
                                ui_msg(UiMsg::BadPsw(arc.file_name().to_string(), arc_file_name.clone()));
                            } else {
                                ui_msg(UiMsg::WaitBadPsw(arc.file_name().to_string(), arc_file_name.clone()));
                                self.cmd.borrow_mut().password_clean();
                                continue;
                            }
                            set_error_code(RARX_BADPWD);
                            extr_file = false;
                        }
                    }
                    break;
                }
            } else {
                self.data_io.clear_encryption();
            }

            let cur_convert_symlink_paths = self.convert_symlink_paths;
            let absolute_links = self.cmd.borrow().absolute_links;
            if extr_file && command != 'P' && !test && !absolute_links && cur_convert_symlink_paths {
                let ep = self.cmd.borrow().extr_path.clone();
                extr_file = links_to_dirs(&self.dest_file_name, &ep, &mut self.last_checked_symlink);
            }

            let mut cur_file = File::new();
            let link_entry = arc.file_head.redir_type != FsRedir::None;
            if link_entry && arc.file_head.redir_type != FsRedir::FileCopy {
                if self.cmd.borrow().skip_sym_links
                    && matches!(arc.file_head.redir_type, FsRedir::UnixSymlink | FsRedir::WinSymlink | FsRedir::Junction)
                {
                    extr_file = false;
                }
                if extr_file && command != 'P' && !test && file_exist(&self.dest_file_name) {
                    let mut d = self.dest_file_name.clone();
                    let (_, reject) = {
                        let mut c = self.cmd.borrow_mut();
                        file_create(&mut c, None, &mut d, Some(arc.file_head.unp_size), Some(&arc.file_head.mtime), FILECR_DEFAULT)
                    };
                    self.dest_file_name = d;
                    if reject {
                        extr_file = false;
                    }
                }
            } else if arc.is_arc_dir() {
                let excl_skip = self.cmd.borrow().excl_path == PathExclMode::SkipWholePath;
                if !extr_file || command == 'P' || command == 'I' || command == 'E' || excl_skip {
                    return true;
                }
                self.total_file_count += 1;
                self.extr_create_dir(arc, &arc_file_name);
                return true;
            } else if extr_file {
                if !self.check_win_limit(arc, &arc_file_name) {
                    return false;
                }
                if cfg!(windows) {
                    // Hidden, system, archive and not indexed attributes can be
                    // set only when creating a file.
                    let mut a = arc.file_head.file_attr & (0x2 | 0x4 | 0x20 | 0x2000);
                    if self.cmd.borrow().clear_arc {
                        a &= !0x20;
                    }
                    if !self.cmd.borrow().ignore_general_attr {
                        cur_file.create_attr = a;
                    }
                }
                extr_file = self.extr_create_file(arc, &mut cur_file, true);
            }

            if !extr_file && arc.solid {
                skip_solid = true;
                extr_file = true;
                if !self.check_win_limit(arc, &arc_file_name) {
                    return false;
                }
            }
            if extr_file {
                if test {
                    self.prev_processed = true;
                }
                let test_mode = test || skip_solid;
                if !skip_solid {
                    if !test_mode && command != 'P' && cur_file.is_device() {
                        ui_msg(UiMsg::InvalidName(arc.file_name().to_string(), self.dest_file_name.clone()));
                        errhnd::write_error(arc.file_name(), &self.dest_file_name);
                    }
                    self.total_file_count += 1;
                }
                self.file_count += 1;
                let (disable_names, disable_percentage, keep_broken) = {
                    let c = self.cmd.borrow();
                    (c.disable_names, c.disable_percentage, c.keep_broken)
                };
                if command != 'I' && !disable_names {
                    if skip_solid {
                        mprintf(&wfmt!(MExtrSkipFile, arc_file_name.as_str()));
                    } else {
                        match if test { 'T' } else { command } {
                            'T' => mprintf(&wfmt!(MExtrTestFile, arc_file_name.as_str())),
                            'P' => mprintf(&wfmt!(MExtrPrinting, arc_file_name.as_str())),
                            'X' | 'E' => mprintf(&wfmt!(MExtrFile, self.dest_file_name.as_str())),
                            _ => {}
                        }
                    }
                }
                if !disable_percentage && !disable_names {
                    mprintf("     ");
                }
                if disable_names {
                    ui_eol_after_msg();
                }
                self.data_io.cur_unp_read = 0;
                self.data_io.cur_unp_write = 0;
                self.data_io.unp_hash.init(arc.file_head.file_hash.kind);
                self.data_io.packed_data_hash.init(arc.file_head.file_hash.kind);
                self.data_io.set_packed_size_to_read(arc.file_head.pack_size);
                self.data_io.set_sub_header(false);
                self.data_io.reset_percent();
                self.data_io.set_test_mode(test_mode);
                self.data_io.set_skip_unp_crc(skip_solid);
                cur_file.set_allow_delete(!keep_broken);

                let file_create_mode = !test_mode && !skip_solid && command != 'P';
                let mut show_checksum = true;
                let mut link_success = true;
                if link_entry {
                    let t = arc.file_head.redir_type;
                    if t == FsRedir::Hardlink || t == FsRedir::FileCopy {
                        let redir = slash_to_native(&arc.file_head.redir_name);
                        let (_, redir) = convert_path(&redir);
                        let mut name_existing = String::new();
                        self.extr_prepare_name(arc, &redir, &mut name_existing);
                        if file_create_mode && !name_existing.is_empty() {
                            if t == FsRedir::Hardlink {
                                let c = self.cmd.borrow().clone();
                                link_success = extract_hardlink(&c, &self.dest_file_name, &name_existing);
                            } else {
                                let an = arc.file_name().to_string();
                                let d = self.dest_file_name.clone();
                                link_success = self.extract_file_copy(&mut cur_file, &an, &redir, &d, &name_existing, arc.file_head.unp_size);
                            }
                        }
                    } else if matches!(t, FsRedir::UnixSymlink | FsRedir::WinSymlink | FsRedir::Junction) {
                        if file_create_mode {
                            let mut up_link = false;
                            let c = self.cmd.borrow().clone();
                            let d = self.dest_file_name.clone();
                            link_success = extract_symlink(&c, &mut self.data_io, arc, &d, &mut up_link);
                            self.convert_symlink_paths |= link_success && up_link;
                            self.last_checked_symlink.clear();
                        }
                    } else {
                        ui_msg(UiMsg::UnknownExtra(arc.file_name().to_string(), arc_file_name.clone()));
                        link_success = false;
                    }
                    if !link_success || arc.format == RarFormat::Rar15 && !file_create_mode {
                        show_checksum = false;
                    }
                    self.prev_processed = file_create_mode && link_success;
                } else if !arc.file_head.split_before {
                    let unp_size = arc.file_head.unp_size;
                    let method = arc.file_head.method;
                    let unp_ver = arc.file_head.unp_ver;
                    let solid_flag = arc.file_head.solid;
                    let win_size = arc.file_head.win_size;
                    let rar14_15 = arc.format != RarFormat::Rar50 && unp_ver <= 15;
                    let arc_solid = arc.solid;
                    let fc = self.file_count;
                    if method == 0 {
                        let mut ctx = DataIoCtx { io: &mut self.data_io, arc, dest: Some(&mut cur_file) };
                        unstore_file(&mut ctx, unp_size);
                    } else {
                        if self.unp.init(win_size, solid_flag).is_err() {
                            if win_size >= 0x40000000 {
                                let gb = (win_size / 0x40000000 + if !win_size.is_multiple_of(0x40000000) { 1 } else { 0 }) as u32;
                                ui_msg(UiMsg::ExtrDictOutMem(arc.file_name().to_string(), gb));
                            }
                            errhnd::bad_alloc();
                        }
                        self.unp.set_dest_size(unp_size);
                        let mut ctx = DataIoCtx { io: &mut self.data_io, arc, dest: Some(&mut cur_file) };
                        if rar14_15 {
                            self.unp.do_unpack(15, fc > 1 && arc_solid, &mut ctx);
                        } else {
                            self.unp.do_unpack(unp_ver, solid_flag, &mut ctx);
                        }
                    }
                }
                arc.seek_to_next();

                let key = if arc.file_head.use_hash_key { Some(&arc.file_head.hash_key) } else { None };
                let valid_crc = !arc.file_head.split_after && self.data_io.unp_hash.cmp(&arc.file_head.file_hash, key);
                if !arc.file_head.solid {
                    self.any_solid_data_unpacked_well = false;
                } else if arc.file_head.method != 0 && arc.file_head.unp_size > 0 && valid_crc {
                    self.any_solid_data_unpacked_well = true;
                }
                let mut broken_file = false;
                if !skip_solid && show_checksum {
                    if valid_crc {
                        if command != 'P' && command != 'I' && !disable_names {
                            let ok = if arc.file_head.file_hash.kind == HashType::None { "  ?" } else { MOk };
                            mprintf(&wfmt!("%s%s ", if disable_percentage { " " } else { "\x08\x08\x08\x08\x08 " }, ok));
                        }
                    } else {
                        if arc.file_head.encrypted
                            && (!arc.file_head.use_psw_check || arc.broken_header)
                            && !self.any_solid_data_unpacked_well
                        {
                            ui_msg(UiMsg::ChecksumEnc(arc.file_name().to_string(), arc_file_name.clone()));
                        } else {
                            ui_msg(UiMsg::Checksum(arc.file_name().to_string(), arc_file_name.clone()));
                        }
                        broken_file = true;
                        set_error_code(RARX_CRC);
                    }
                } else if skip_solid {
                    mprintf("\x08\x08\x08\x08\x08     ");
                }
                if !test_mode && (command == 'X' || command == 'E') && (!link_entry || link_success) && (!broken_file || keep_broken) {
                    let set_all = !link_entry || arc.file_head.redir_type == FsRedir::FileCopy;
                    let set_time_and_size = set_all;
                    let set_attr = set_all || arc.file_head.redir_type == FsRedir::Hardlink;
                    let set_extra = set_all || arc.file_head.redir_type == FsRedir::UnixSymlink;
                    let c = self.cmd.borrow().clone();
                    let mtime = if c.xmtime == ExtTimeMode::None { None } else { Some(arc.file_head.mtime) };
                    let atime = if c.xatime == ExtTimeMode::None { None } else { Some(arc.file_head.atime) };
                    let ctime = if c.xctime == ExtTimeMode::None { None } else { Some(arc.file_head.ctime) };
                    if set_time_and_size {
                        if cfg!(windows) {
                            arc.motw.create_zone_id_stream(&self.dest_file_name, &c.motw_list);
                            if c.set_compressed_attr && arc.file_head.file_attr & crate::winsys::FILE_ATTRIBUTE_COMPRESSED != 0 {
                                crate::winsys::set_compression(&self.dest_file_name);
                            }
                        }
                        cur_file.keep();
                        cur_file.close();
                    }
                    if set_extra {
                        let d = self.dest_file_name.clone();
                        set_file_header_extra(&c, arc, &d);
                    }
                    if set_time_and_size {
                        crate::file::set_file_times_by_name(&self.dest_file_name, mtime.as_ref(), ctime.as_ref(), atime.as_ref());
                    }
                    if set_attr {
                        let mut attr = arc.file_head.file_attr;
                        if cfg!(windows) && c.clear_arc {
                            attr &= !0x20;
                        }
                        if cfg!(unix) && geteuid() != 0 {
                            attr &= !(0o4000 | 0o2000);
                        }
                        if !c.ignore_general_attr && !set_file_attr(&self.dest_file_name, attr) {
                            ui_msg(UiMsg::FileAttr(arc.file_name().to_string(), self.dest_file_name.clone()));
                            sys_err_msg();
                        }
                    }
                    self.prev_processed = true;
                }
                if !cur_file.is_std() && cur_file.is_opened() && keep_broken {
                    cur_file.keep();
                }
            }
        }
        if match_found {
            self.matched_args += 1;
        }
        if self.data_io.next_volume_missing {
            return false;
        }
        if !extr_file {
            if !arc.solid {
                arc.seek_to_next();
            } else if !skip_solid {
                return false;
            }
        }
        true
    }

    fn extract_file_copy(&mut self, new: &mut File, arc_name: &str, redir_name: &str, name_new: &str, name_existing: &str, unp_size: i64) -> bool {
        let mut existing = File::new();
        if !existing.open(name_existing, 0) {
            let mut tmp_existing = name_existing.to_string();
            let mut open_failed = true;
            for i in 0..self.ref_list.len() {
                if redir_name == self.ref_list[i].ref_name && !self.ref_list[i].tmp_name.is_empty() {
                    let ref_move = self.ref_list[i].ref_count == 1;
                    self.ref_list[i].ref_count = self.ref_list[i].ref_count.saturating_sub(1);
                    tmp_existing = self.ref_list[i].tmp_name.clone();
                    let mut moved = false;
                    if ref_move {
                        new.delete();
                        if !rename_file(&tmp_existing, name_new) {
                            if !new.w_create(name_new, crate::file::FMF_WRITE | crate::file::FMF_SHAREREAD) {
                                return false;
                            }
                        } else {
                            if new.open(name_new, crate::file::FMF_UPDATE) {
                                new.seek(0, crate::file::SEEK_END);
                            }
                            self.ref_list[i].tmp_name.clear();
                            moved = true;
                        }
                    }
                    if moved {
                        return true;
                    }
                    open_failed = !existing.open(&tmp_existing, 0);
                    break;
                }
            }
            if open_failed {
                errhnd::open_error_msg("", &tmp_existing);
                ui_msg(UiMsg::FileCopy(arc_name.to_string(), tmp_existing, name_new.to_string()));
                ui_msg(UiMsg::FileCopyHint(arc_name.to_string()));
                return false;
            }
        }
        let mut buf = vec![0u8; 0x100000];
        let mut copy_size = 0i64;
        loop {
            errhnd::wait();
            let r = existing.read(&mut buf);
            if r <= 0 {
                break;
            }
            ui_extract_progress(copy_size, unp_size, 0, 0);
            new.write(&buf[..r as usize]);
            copy_size += r as i64;
        }
        true
    }

    fn extr_prepare_name(&mut self, arc: &Archive, arc_file_name: &str, dest_name: &mut String) {
        if arc_file_name.is_empty() {
            dest_name.clear();
            return;
        }
        let c = self.cmd.borrow();
        if c.test {
            *dest_name = arc_file_name.to_string();
            return;
        }
        *dest_name = c.extr_path.clone();
        if !c.extr_path.is_empty() {
            let last = get_last_char(&c.extr_path);
            if !is_path_div(last) && !is_drive_div(last) {
                add_end_slash(dest_name);
            }
        }
        if c.append_arc_name_to_path != AppendArcName::None {
            match c.append_arc_name_to_path {
                AppendArcName::DestPath => {
                    dest_name.push_str(point_to_name(&arc.first_volume_name));
                    remove_ext(dest_name);
                }
                AppendArcName::OwnSubdir => {
                    *dest_name = arc.first_volume_name.clone();
                    remove_ext(dest_name);
                }
                AppendArcName::OwnDir => {
                    *dest_name = arc.first_volume_name.clone();
                    remove_name_from_path(dest_name);
                }
                AppendArcName::None => {}
            }
            add_end_slash(dest_name);
        }
        let mut cur_name = chars(arc_file_name);
        let arc_path = if !c.excl_arc_path.is_empty() { c.excl_arc_path.clone() } else { c.arc_path.clone() };
        let ap = chars(&arc_path);
        if !ap.is_empty() {
            let nl = cur_name.len();
            if nl >= ap.len()
                && wcsnicompc_eq(&ap, &cur_name, ap.len())
                && (is_path_div(ap[ap.len() - 1]) || is_path_div(at(&cur_name, ap.len())) || at(&cur_name, ap.len()) == '\0')
            {
                let mut pos = ap.len().min(nl);
                while pos < cur_name.len() && is_path_div(cur_name[pos]) {
                    pos += 1;
                }
                cur_name.drain(..pos);
                if cur_name.is_empty() {
                    dest_name.clear();
                    return;
                }
            }
        }
        let command = c.cmd_char();
        let mut abs_paths = c.excl_path == PathExclMode::AbsPath && command == 'X' && is_drive_div(':');
        if abs_paths {
            let disk = toupperw(at(&cur_name, 0));
            if disk.is_ascii_uppercase() && at(&cur_name, 1) == '_' && is_path_div(at(&cur_name, 2)) {
                *dest_name = format!("{}:{}", cur_name[0], cur_name[2..].iter().collect::<String>());
            } else if at(&cur_name, 0) == '_' && at(&cur_name, 1) == '_' {
                *dest_name = format!("{}{}{}", CPATHDIVIDER, CPATHDIVIDER, cur_name[2..].iter().collect::<String>());
            } else {
                abs_paths = false;
            }
        }
        let mut cur: String = cur_name.iter().collect();
        if command == 'E' || c.excl_path == PathExclMode::SkipWholePath {
            cur = point_to_name(&cur).to_string();
        }
        if !abs_paths {
            dest_name.push_str(&cur);
        }
        if cfg!(windows) && !c.allow_incompat_names {
            make_name_compatible(dest_name);
        }
    }

    fn extr_get_password(&mut self, arc: &Archive, arc_file_name: &str) -> bool {
        if !self.cmd.borrow().password_set() {
            match crate::consio::get_console_password(crate::consio::PasswordType::File, arc_file_name) {
                Some(p) if !p.is_empty() => {
                    let mut c = self.cmd.borrow_mut();
                    c.password = Some(p);
                    c.manual_password = true;
                }
                _ => {
                    ui_msg(UiMsg::IncErrCount);
                    return false;
                }
            }
        } else if !self.global_password && !arc.file_head.solid {
            eprintf(&wfmt!(MUseCurPsw, arc_file_name));
            let all_yes = self.cmd.borrow().all_yes;
            match if all_yes { 1 } else { ask(MYesNoAll) } {
                -1 => errhnd::exit(RARX_USERBREAK),
                2 => match crate::consio::get_console_password(crate::consio::PasswordType::File, arc_file_name) {
                    Some(p) if !p.is_empty() => self.cmd.borrow_mut().password = Some(p),
                    _ => return false,
                },
                3 => self.global_password = true,
                _ => {}
            }
        }
        true
    }

    fn extr_create_dir(&mut self, arc: &mut Archive, arc_file_name: &str) {
        let c = self.cmd.borrow().clone();
        if c.test {
            if !c.disable_names {
                mprintf(&wfmt!(MExtrTestFile, arc_file_name));
                mprintf(&wfmt!(" %s", MOk));
            }
            return;
        }
        let mut file_attr = arc.file_head.file_attr;
        if cfg!(unix) && geteuid() != 0 {
            file_attr &= !0o4000;
        }
        let mut md = make_dir(&self.dest_file_name, !c.ignore_general_attr, file_attr);
        let mut dir_exist = false;
        if md != MkdirCode::Success {
            dir_exist = file_exist(&self.dest_file_name);
            if dir_exist && !is_dir(get_file_attr(&self.dest_file_name)) {
                let mut d = self.dest_file_name.clone();
                {
                    let mut cm = self.cmd.borrow_mut();
                    file_create(&mut cm, None, &mut d, Some(arc.file_head.unp_size), Some(&arc.file_head.mtime), FILECR_FOLDER);
                }
                self.dest_file_name = d;
                dir_exist = false;
            }
            if !dir_exist {
                create_path(&self.dest_file_name, true, c.disable_names);
                md = make_dir(&self.dest_file_name, !c.ignore_general_attr, file_attr);
                if md != MkdirCode::Success && !is_name_usable(&self.dest_file_name) {
                    ui_msg(UiMsg::CorrectingName(arc.file_name().to_string()));
                    let orig = self.dest_file_name.clone();
                    make_name_usable(&mut self.dest_file_name, true);
                    ui_msg(UiMsg::Renaming(arc.file_name().to_string(), orig, self.dest_file_name.clone()));
                    dir_exist = file_exist(&self.dest_file_name) && is_dir(get_file_attr(&self.dest_file_name));
                    if !dir_exist
                        && (c.absolute_links
                            || !self.convert_symlink_paths
                            || links_to_dirs(&self.dest_file_name, &c.extr_path, &mut self.last_checked_symlink))
                    {
                        create_path(&self.dest_file_name, true, c.disable_names);
                        md = make_dir(&self.dest_file_name, !c.ignore_general_attr, file_attr);
                    }
                }
            }
        }
        if md == MkdirCode::Success {
            if !c.disable_names {
                mprintf(&wfmt!(MCreatDir, self.dest_file_name.as_str()));
                mprintf(&wfmt!(" %s", MOk));
            }
            if cfg!(unix) && !c.ignore_general_attr {
                set_file_attr(&self.dest_file_name, file_attr);
            }
            self.prev_processed = true;
        } else if dir_exist {
            if !c.ignore_general_attr {
                set_file_attr(&self.dest_file_name, file_attr);
            }
            self.prev_processed = true;
        } else {
            ui_msg(UiMsg::DirCreate(arc.file_name().to_string(), self.dest_file_name.clone()));
            sys_err_msg();
            set_error_code(RARX_CREATE);
        }
        if self.prev_processed {
            let d = self.dest_file_name.clone();
            if cfg!(windows) && c.set_compressed_attr && file_attr & crate::winsys::FILE_ATTRIBUTE_COMPRESSED != 0 {
                crate::winsys::set_compression(&d);
            }
            set_file_header_extra(&c, arc, &d);
            let mtime = if c.xmtime == ExtTimeMode::None { None } else { Some(arc.file_head.mtime) };
            let ctime = if c.xctime == ExtTimeMode::None { None } else { Some(arc.file_head.ctime) };
            let atime = if c.xatime == ExtTimeMode::None { None } else { Some(arc.file_head.atime) };
            set_dir_time(&d, mtime.as_ref(), ctime.as_ref(), atime.as_ref());
        }
    }

    fn extr_create_file(&mut self, arc: &Archive, cur_file: &mut File, write_only: bool) -> bool {
        let command = self.cmd.borrow().cmd_char();
        let test = self.cmd.borrow().test;
        let mut success = true;
        if command == 'P' {
            cur_file.set_handle_std();
        }
        if (command == 'E' || command == 'X') && !test {
            let flags = if write_only { FILECR_WRITEONLY } else { FILECR_DEFAULT };
            let mut d = self.dest_file_name.clone();
            let (ok, reject) = {
                let mut c = self.cmd.borrow_mut();
                file_create(&mut c, Some(cur_file), &mut d, Some(arc.file_head.unp_size), Some(&arc.file_head.mtime), flags)
            };
            self.dest_file_name = d;
            if !ok {
                success = false;
                if !reject {
                    errhnd::create_error_msg(arc.file_name(), &self.dest_file_name);
                    if file_exist(&self.dest_file_name) && is_dir(get_file_attr(&self.dest_file_name)) {
                        ui_msg(UiMsg::DirNameExists);
                    }
                    if !is_name_usable(&self.dest_file_name) {
                        ui_msg(UiMsg::CorrectingName(arc.file_name().to_string()));
                        let orig = self.dest_file_name.clone();
                        make_name_usable(&mut self.dest_file_name, true);
                        let (absolute_links, ep, disable_names) = {
                            let c = self.cmd.borrow();
                            (c.absolute_links, c.extr_path.clone(), c.disable_names)
                        };
                        if absolute_links || !self.convert_symlink_paths || links_to_dirs(&self.dest_file_name, &ep, &mut self.last_checked_symlink) {
                            create_path(&self.dest_file_name, true, disable_names);
                            let mut d = self.dest_file_name.clone();
                            let (ok, _) = {
                                let mut c = self.cmd.borrow_mut();
                                file_create(&mut c, Some(cur_file), &mut d, Some(arc.file_head.unp_size), Some(&arc.file_head.mtime), flags)
                            };
                            self.dest_file_name = d;
                            if ok {
                                ui_msg(UiMsg::Renaming(arc.file_name().to_string(), orig, self.dest_file_name.clone()));
                                success = true;
                            } else {
                                errhnd::create_error_msg(arc.file_name(), &self.dest_file_name);
                            }
                        }
                    }
                }
            }
        }
        success
    }

    fn check_unp_ver(&self, arc: &Archive, arc_file_name: &str) -> bool {
        let fh = &arc.file_head;
        let mut wrong = if arc.format == RarFormat::Rar50 {
            fh.unp_ver > VER_UNPACK7
        } else {
            fh.unp_ver < 13 || fh.unp_ver > VER_UNPACK
        };
        if fh.method == 0 {
            wrong = false;
        }
        if fh.crypt_method == CryptMethod::Unknown {
            wrong = true;
        }
        if wrong {
            errhnd::unknown_method_msg(arc.file_name(), arc_file_name);
            if !arc.broken_header {
                ui_msg(UiMsg::NewerRar(arc.file_name().to_string()));
            }
        }
        !wrong
    }

    fn analyze_archive(&mut self, arc_name: &str, volume: bool, new_numbering: bool) {
        self.free_analyze_data();
        {
            let c = self.cmd.borrow();
            if let Some(a) = c.file_args.get_string_num(0) {
                if a == "*" || a == "*.*" {
                    return;
                }
            }
        }
        let mut next_name = if volume { self.get_first_vol_if_full_set(arc_name, new_numbering) } else { arc_name.to_string() };
        let mut match_found = false;
        let mut prev_matched = false;
        let mut open_next = false;
        let mut first_volume = true;
        let mut first_file = true;
        loop {
            let mut arc = Archive::new(self.cmd.clone());
            if !arc.open(&next_name, 0) || !arc.is_archive(false) {
                if open_next {
                    self.analyze.end_name.clear();
                    self.analyze.end_pos = 0;
                }
                break;
            }
            open_next = false;
            while arc.read_header() > 0 {
                crate::errhnd::wait();
                let ht = arc.get_header_type();
                if ht == HEAD_ENDARC {
                    open_next |= arc.end_arc_head.next_volume;
                    break;
                }
                if ht == HEAD_FILE {
                    if (arc.format == RarFormat::Rar14 || arc.format == RarFormat::Rar15) && arc.file_head.unp_ver <= 15 {
                        open_next = false;
                        break;
                    }
                    if !arc.file_head.split_before {
                        if !match_found
                            && !arc.file_head.solid
                            && !arc.file_head.dir
                            && arc.file_head.redir_type == FsRedir::None
                            && arc.file_head.method != 0
                        {
                            if !first_volume {
                                self.analyze.start_name = next_name.clone();
                            }
                            if !first_file {
                                self.analyze.start_pos = arc.cur_block_pos as u64;
                            }
                        }
                        if self.cmd.borrow().is_process_file(&arc.file_head, None, MATCH_WILDSUBPATH, None) != 0 {
                            match_found = true;
                            prev_matched = true;
                            self.analyze.end_pos = 0;
                            if arc.file_head.redir_type == FsRedir::FileCopy {
                                let mut added = false;
                                for r in self.ref_list.iter_mut() {
                                    if arc.file_head.redir_name == r.ref_name {
                                        r.ref_count += 1;
                                        added = true;
                                        break;
                                    }
                                }
                                if !added && self.ref_list.len() < 1000000 {
                                    self.ref_list.push(ExtractRef {
                                        ref_name: arc.file_head.redir_name.clone(),
                                        tmp_name: String::new(),
                                        ref_count: 1,
                                    });
                                }
                            }
                        } else {
                            if prev_matched {
                                if !first_volume {
                                    self.analyze.end_name = next_name.clone();
                                }
                                self.analyze.end_pos = arc.cur_block_pos as u64;
                            }
                            prev_matched = false;
                        }
                    }
                    first_file = false;
                    if arc.file_head.split_after {
                        open_next = true;
                        break;
                    }
                }
                arc.seek_to_next();
            }
            arc.close();
            if volume && open_next {
                next_volume_name(&mut next_name, !arc.new_numbering);
                first_volume = false;
                first_file = false;
            } else {
                break;
            }
        }
        if !self.ref_list.is_empty() {
            self.analyze = AnalyzeData::default();
        }
    }

    fn get_first_vol_if_full_set(&self, src_name: &str, new_numbering: bool) -> String {
        let (first, _) = vol_name_to_first_name(src_name, new_numbering);
        let mut next = first.clone();
        let mut result = src_name.to_string();
        loop {
            if src_name == next {
                result = first;
                break;
            }
            if !file_exist(&next) {
                break;
            }
            next_volume_name(&mut next, !new_numbering);
        }
        result
    }

    fn check_win_limit(&mut self, arc: &mut Archive, arc_file_name: &str) -> bool {
        let (limit, ws) = {
            let c = self.cmd.borrow();
            (c.win_size_limit, c.win_size)
        };
        if arc.file_head.win_size <= limit || arc.file_head.win_size <= ws {
            return true;
        }
        if ui_dict_limit(arc_file_name, arc.file_head.win_size, limit.max(ws)) {
            self.cmd.borrow_mut().win_size_limit = arc.file_head.win_size;
        } else {
            set_error_code(RARX_FATAL);
            arc.seek_to_next();
            return false;
        }
        true
    }
}
