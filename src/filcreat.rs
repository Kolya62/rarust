// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Creating files with overwrite prompts.

use crate::cmddata::{CommandData, OverwriteMode};
use crate::errhnd::{self, RARX_USERBREAK};
use crate::file::{File, FMF_SHAREREAD, FMF_UPDATE, FMF_WRITE};
use crate::filefn::*;
use crate::find::{fast_find, FindData};
use crate::pathfn::*;
use crate::timefn::RarTime;
use crate::ui::*;

pub const FILECR_DEFAULT: u32 = 0;
pub const FILECR_WRITEONLY: u32 = 1;
pub const FILECR_FOLDER: u32 = 2;

pub fn get_auto_renamed_name(name: &mut String) -> bool {
    let ext = get_ext(name).to_string();
    for ver in 1..1000000u32 {
        let mut n = name.clone();
        remove_ext(&mut n);
        n = format!("{}({}){}", n, ver, ext);
        if !file_exist(&n) {
            *name = n;
            return true;
        }
    }
    false
}

/// Ask about overwriting and adjust command options. Returns only
/// Replace, Skip and Cancel.
pub fn ui_ask_replace_ex(cmd: &mut CommandData, name: &mut String, size: Option<i64>, time: Option<&RarTime>, flags: u32) -> AskRep {
    if cmd.overwrite == OverwriteMode::None {
        return AskRep::Skip;
    }
    if cmd.overwrite == OverwriteMode::AutoRename && get_auto_renamed_name(name) {
        return AskRep::Replace;
    }
    let mut new_name = name.clone();
    let choice = if cmd.all_yes || cmd.overwrite == OverwriteMode::All {
        AskRep::Replace
    } else {
        ui_ask_replace(&mut new_name, size, time, flags)
    };
    if choice == AskRep::Replace || choice == AskRep::ReplaceAll {
        prepare_to_delete(name);
        let mut fd = FindData::default();
        if fast_find(name, &mut fd, true) {
            if fd.is_link {
                del_file(name);
            } else if fd.is_dir {
                del_dir(name);
            }
        }
    }
    match choice {
        AskRep::ReplaceAll => {
            cmd.overwrite = OverwriteMode::All;
            AskRep::Replace
        }
        AskRep::SkipAll => {
            cmd.overwrite = OverwriteMode::None;
            AskRep::Skip
        }
        AskRep::Rename => {
            if get_name_pos(&new_name) == 0 {
                set_name(name, &new_name);
            } else {
                *name = new_name;
            }
            if file_exist(name) {
                return ui_ask_replace_ex(cmd, name, size, time, flags);
            }
            AskRep::Replace
        }
        AskRep::RenameAuto => {
            if get_auto_renamed_name(name) {
                cmd.overwrite = OverwriteMode::AutoRename;
                return AskRep::Replace;
            }
            AskRep::RenameAuto
        }
        c => c,
    }
}

/// Create a file, asking about overwriting. If `new_file` is None, delete
/// existing file or folder after confirmation. Returns (success, user_reject).
pub fn file_create(cmd: &mut CommandData, new_file: Option<&mut File>, name: &mut String, size: Option<i64>, time: Option<&RarTime>, flags: u32) -> (bool, bool) {
    let write_only = flags & FILECR_WRITEONLY != 0;
    let has_file = new_file.is_some();
    while file_exist(name) {
        let mut ask_flags = if has_file { 0 } else { UIASKREP_F_NORENAME };
        if flags & FILECR_FOLDER != 0 {
            ask_flags |= UIASKREP_F_SRCFOLDER;
        }
        let choice = ui_ask_replace_ex(cmd, name, size, time, ask_flags);
        if choice == AskRep::Replace {
            break;
        }
        if choice == AskRep::Skip {
            return (false, true);
        }
        if choice == AskRep::Cancel {
            errhnd::exit(RARX_USERBREAK);
        }
    }
    let mode = if write_only { FMF_WRITE | FMF_SHAREREAD } else { FMF_UPDATE | FMF_SHAREREAD };
    match new_file {
        Some(f) => {
            if f.create(name, mode) {
                return (true, false);
            }
            create_path(name, true, cmd.disable_names);
            (f.create(name, mode), false)
        }
        None => {
            create_path(name, true, cmd.disable_names);
            (del_file(name), false)
        }
    }
}
