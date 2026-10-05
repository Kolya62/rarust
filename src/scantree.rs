// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Recursive file search by masks.

use crate::cmddata::{CommandData, RecurseMode};
use crate::find::{fast_find, FindData, FindFile};
use crate::matchfn::{cmp_name, MATCH_NAMES, MATCH_WILDSUBPATH};
use crate::pathfn::*;
use crate::strlist::StringList;
use crate::ui::{ui_msg, UiMsg};

pub const MASKALL: &str = "*";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ScanDirs {
    SkipDirs,
    GetDirs,
    GetDirsTwice,
    GetCurDirs,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ScanCode {
    Success,
    Done,
    Error,
    Next,
}

pub const FDDF_SECONDDIR: u32 = 1;

pub struct ScanTree<'a> {
    find_stack: Vec<Option<FindFile>>,
    depth: i32,
    set_all_mask_depth: i32,
    file_masks: StringList,
    recurse: RecurseMode,
    get_links: bool,
    get_dirs: ScanDirs,
    errors: u32,
    scan_entire_disk: bool,
    cur_mask: String,
    orig_cur_mask: String,
    expanded_folder_list: StringList,
    filter_list: StringList,
    folder_wildcards: bool,
    search_all_in_root: bool,
    spec_path_length: usize,
    err_arc_name: String,
    cmd: Option<&'a CommandData>,
}

impl<'a> ScanTree<'a> {
    pub fn new(masks: &StringList, recurse: RecurseMode, get_links: bool, get_dirs: ScanDirs) -> Self {
        let mut m = masks.clone();
        m.rewind();
        ScanTree {
            find_stack: vec![None],
            depth: 0,
            set_all_mask_depth: 0,
            file_masks: m,
            recurse,
            get_links,
            get_dirs,
            errors: 0,
            scan_entire_disk: false,
            cur_mask: String::new(),
            orig_cur_mask: String::new(),
            expanded_folder_list: StringList::new(),
            filter_list: StringList::new(),
            folder_wildcards: false,
            search_all_in_root: false,
            spec_path_length: 0,
            err_arc_name: String::new(),
            cmd: None,
        }
    }

    pub fn set_command_data(&mut self, cmd: &'a CommandData) {
        self.cmd = Some(cmd);
    }

    pub fn get_errors(&self) -> u32 {
        self.errors
    }

    pub fn get_spec_path_length(&self) -> usize {
        self.spec_path_length
    }

    pub fn get_next(&mut self, fd: &mut FindData) -> ScanCode {
        if self.depth < 0 {
            return ScanCode::Done;
        }
        let mut code;
        let mut loop_count = 0u32;
        loop {
            if self.cur_mask.is_empty() && !self.get_next_mask() {
                return ScanCode::Done;
            }
            loop_count = loop_count.wrapping_add(1);
            if loop_count & 0x3ff == 0 {
                crate::errhnd::wait();
            }
            code = self.find_proc(fd);
            if code == ScanCode::Error {
                self.errors += 1;
                continue;
            }
            if code == ScanCode::Next {
                continue;
            }
            if code == ScanCode::Success && fd.is_dir && self.get_dirs == ScanDirs::SkipDirs {
                continue;
            }
            if code == ScanCode::Done && self.get_next_mask() {
                continue;
            }
            if self.filter_list.items_count() > 0
                && code == ScanCode::Success
                && !CommandData::check_args(&self.filter_list, fd.is_dir, &fd.name, false, MATCH_WILDSUBPATH)
            {
                continue;
            }
            break;
        }
        code
    }

    fn expand_folder_mask(&mut self) -> bool {
        let v = chars(&self.cur_mask);
        let mut wildcard = false;
        let mut slash_pos = 0;
        for (i, &c) in v.iter().enumerate() {
            if c == '?' || c == '*' {
                wildcard = true;
            }
            if wildcard && is_path_div(c) {
                slash_pos = i;
                break;
            }
        }
        let mask: String = v[..slash_pos].iter().collect();
        let rest: String = v[slash_pos..].iter().collect();
        self.expanded_folder_list.reset();
        let mut find = FindFile::new();
        find.set_mask(&mask);
        let mut fd = FindData::default();
        while find.next(&mut fd, false) {
            if fd.is_dir {
                fd.name.push_str(&rest);
                let last = point_to_name(&fd.name).to_string();
                if last == "*" || last == "*.*" || last.is_empty() {
                    remove_name_from_path(&mut fd.name);
                }
                self.expanded_folder_list.add_string(&fd.name);
            }
        }
        if self.expanded_folder_list.items_count() == 0 {
            return false;
        }
        self.cur_mask = self.expanded_folder_list.get_string().unwrap();
        true
    }

    fn get_filtered_mask(&mut self) -> bool {
        if self.expanded_folder_list.items_count() > 0 {
            if let Some(m) = self.expanded_folder_list.get_string() {
                self.cur_mask = m;
                return true;
            }
        }
        self.folder_wildcards = false;
        self.filter_list.reset();
        match self.file_masks.get_string() {
            Some(m) => self.cur_mask = m,
            None => return false,
        }
        let v = chars(&self.cur_mask);
        let mut wildcard = false;
        let mut count = 0;
        let mut slash_pos = 0;
        for (i, &c) in v.iter().enumerate() {
            if c == '?' || c == '*' {
                wildcard = true;
            }
            if is_path_div(c) || is_drive_div(c) {
                if wildcard {
                    count += 1;
                    wildcard = false;
                }
                if count == 0 {
                    slash_pos = i;
                }
            }
        }
        if count == 0 {
            return true;
        }
        self.folder_wildcards = true;
        if (self.recurse == RecurseMode::None || self.recurse == RecurseMode::Disable) && count == 1 {
            return self.expand_folder_mask();
        }
        let mut filter = "*".to_string();
        add_end_slash(&mut filter);
        let sp = at(&v, slash_pos);
        let wild_name: String =
            if is_path_div(sp) || is_drive_div(sp) { v[slash_pos + 1..].iter().collect() } else { v[slash_pos..].iter().collect() };
        filter.push_str(&wild_name);
        let last = point_to_name(&filter).to_string();
        if last == "*" || last == "*.*" {
            filter = get_path_with_sep(&filter);
        }
        self.filter_list.add_string(&filter);
        let relative_drive = is_drive_div(sp);
        let mut sp2 = slash_pos;
        if relative_drive {
            sp2 += 1;
        }
        self.cur_mask = v[..sp2].iter().collect();
        if !relative_drive {
            add_end_slash(&mut self.cur_mask);
            self.cur_mask.push_str(MASKALL);
        }
        true
    }

    fn get_next_mask(&mut self) -> bool {
        if !self.get_filtered_mask() {
            return false;
        }
        self.spec_path_length = get_name_pos(&self.cur_mask);
        let v = chars(&self.cur_mask);
        if self.recurse != RecurseMode::Disable {
            if v.len() > 2 && v[0] == CPATHDIVIDER && v[1] == CPATHDIVIDER {
                if let Some(s) = v[2..].iter().position(|&c| c == CPATHDIVIDER).map(|p| p + 2) {
                    let s2 = v[s + 1..].iter().position(|&c| c == CPATHDIVIDER).map(|p| p + s + 1);
                    self.scan_entire_disk = s2.is_none() || s2.unwrap() + 1 == v.len();
                    if s2.is_none() {
                        self.cur_mask.push(CPATHDIVIDER);
                    }
                }
            } else {
                self.scan_entire_disk = is_drive_letter(&self.cur_mask) && is_path_div(at(&v, 2)) && at(&v, 3) == '\0';
            }
        }
        let name = point_to_name(&self.cur_mask).to_string();
        if name.is_empty() {
            self.cur_mask.push_str(MASKALL);
        }
        if name == "." || name == ".." {
            add_end_slash(&mut self.cur_mask);
            self.cur_mask.push_str(MASKALL);
        }
        self.depth = 0;
        self.orig_cur_mask = self.cur_mask.clone();
        true
    }

    fn find_proc(&mut self, fd: &mut FindData) -> ScanCode {
        if self.cur_mask.is_empty() {
            return ScanCode::Next;
        }
        let mut fast_find_file = false;
        let d = self.depth as usize;
        if self.find_stack[d].is_none() {
            let wildcards = is_wildcard(&self.cur_mask);
            let find_code = !wildcards && fast_find(&self.cur_mask, fd, self.get_links);
            let is_dir_ = find_code && fd.is_dir && (!self.get_links || !fd.is_link);
            let search_all = !is_dir_
                && (self.depth > 0
                    || self.recurse == RecurseMode::Always
                    || self.folder_wildcards && self.recurse != RecurseMode::Disable
                    || wildcards && self.recurse == RecurseMode::Wildcards
                    || self.scan_entire_disk && self.recurse != RecurseMode::Disable);
            if self.depth == 0 {
                self.search_all_in_root = search_all;
            }
            if search_all || wildcards {
                let mut f = FindFile::new();
                let mut search_mask = self.cur_mask.clone();
                if search_all {
                    set_name(&mut search_mask, MASKALL);
                }
                f.set_mask(&search_mask);
                self.find_stack[d] = Some(f);
            } else {
                if !find_code || !is_dir_ || self.recurse == RecurseMode::Disable {
                    let mut ret = ScanCode::Success;
                    if !find_code {
                        ret = if fd.error { ScanCode::Error } else { ScanCode::Next };
                        if self.cmd.map(|c| c.excl_check(&self.cur_mask, false, true, true)).unwrap_or(false) {
                            ret = ScanCode::Next;
                        } else {
                            crate::errhnd::open_error_msg(&self.err_arc_name, &self.cur_mask);
                            crate::errhnd::set_error_code(crate::errhnd::RARX_NOFILES);
                        }
                    }
                    self.cur_mask.clear();
                    return ret;
                }
                fast_find_file = true;
            }
        }
        if !fast_find_file && !self.find_stack[d].as_mut().unwrap().next(fd, self.get_links) {
            let error = fd.error;
            if error {
                self.scan_error();
            }
            self.find_stack[d] = None;
            self.depth -= 1;
            while self.depth >= 0 && self.find_stack[self.depth as usize].is_none() {
                self.depth -= 1;
            }
            if self.depth < 0 {
                if error {
                    self.errors += 1;
                }
                return ScanCode::Done;
            }
            if let Some(slash) = self.cur_mask.rfind(CPATHDIVIDER) {
                let mut mask = self.cur_mask[slash..].to_string();
                if self.depth < self.set_all_mask_depth {
                    mask = format!("{}{}", CPATHDIVIDER, point_to_name(&self.orig_cur_mask));
                }
                self.cur_mask.truncate(slash);
                let dir_name = self.cur_mask.clone();
                match self.cur_mask.rfind(CPATHDIVIDER) {
                    None => self.cur_mask = mask[1..].to_string(),
                    Some(p) => {
                        self.cur_mask.truncate(p);
                        self.cur_mask.push_str(&mask);
                    }
                }
                if self.get_dirs == ScanDirs::GetDirsTwice && fast_find(&dir_name, fd, self.get_links) && fd.is_dir {
                    fd.flags |= FDDF_SECONDDIR;
                    return if error { ScanCode::Error } else { ScanCode::Success };
                }
            }
            return if error { ScanCode::Error } else { ScanCode::Next };
        }
        if fd.is_dir && (!self.get_links || !fd.is_link) {
            if !fast_find_file && self.depth == 0 && !self.search_all_in_root {
                return if self.get_dirs == ScanDirs::GetCurDirs { ScanCode::Success } else { ScanCode::Next };
            }
            if self.cmd.map(|c| c.excl_check(&fd.name, true, false, false)).unwrap_or(false) {
                return if fast_find_file { ScanCode::Done } else { ScanCode::Next };
            }
            let mask = if fast_find_file { MASKALL.to_string() } else { point_to_name(&self.cur_mask).to_string() };
            self.cur_mask = fd.name.clone();
            if self.cur_mask.len() + mask.len() + 1 >= 0x10000 || self.depth >= 0x10000 / 2 - 1 {
                ui_msg(UiMsg::PathTooLong(self.cur_mask.clone(), CPATHDIVIDER.to_string(), mask));
                return ScanCode::Error;
            }
            add_end_slash(&mut self.cur_mask);
            self.cur_mask.push_str(&mask);
            self.depth += 1;
            self.find_stack.resize_with(self.depth as usize + 1, || None);
            if fast_find_file {
                self.set_all_mask_depth = self.depth;
            }
        }
        if !fast_find_file && !cmp_name(&self.cur_mask, &fd.name, MATCH_NAMES) {
            return ScanCode::Next;
        }
        ScanCode::Success
    }

    fn scan_error(&mut self) {
        if self.cmd.map(|c| c.excl_check(&self.cur_mask, false, true, true)).unwrap_or(false) {
            return;
        }
        let mut full = convert_name_to_full(&self.cur_mask);
        remove_name_from_path(&mut full);
        ui_msg(UiMsg::DirScan(full));
        crate::errhnd::sys_err_msg();
    }
}
