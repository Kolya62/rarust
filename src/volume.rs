// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Switching to the next volume of multivolume archive.

use crate::archive::{Archive, RarFormat};
use crate::errhnd::{self, *};
use crate::file::SEEK_SET;
use crate::headers::*;
use crate::loclang::*;
use crate::pathfn::next_volume_name;
use crate::rdwrfn::ComprDataIO;
use crate::ui::{ui_msg, UiMsg};
use crate::wfmt;

pub fn merge_archive(arc: &mut Archive, data_io: Option<&mut ComprDataIO>, show_file_name: bool, command: char) -> bool {
    let cmd = arc.cmd().clone();
    let header_type = arc.get_header_type();
    let use_sub = header_type == HEAD_SERVICE;
    let split_header = (header_type == HEAD_FILE || header_type == HEAD_SERVICE)
        && if use_sub { arc.sub_head.split_after } else { arc.file_head.split_after };
    let mut data_io = data_io;
    if let Some(io) = data_io.as_deref_mut() {
        if split_header {
            let hd = if use_sub { &arc.sub_head } else { &arc.file_head };
            let packed_hash_present = arc.format == RarFormat::Rar50 || hd.unp_ver >= 20 && hd.file_hash.crc32 != 0xffffffff;
            let key = if hd.use_hash_key { Some(&hd.hash_key) } else { None };
            if packed_hash_present && !io.packed_data_hash.cmp(&hd.file_hash, key) {
                ui_msg(UiMsg::ChecksumPacked(arc.file_name().to_string(), hd.file_name.clone()));
            }
        }
    }
    let prev_vol_encrypted = arc.encrypted;
    let pos_before_close = arc.tell();
    if let Some(io) = data_io.as_deref_mut() {
        io.processed_arc_size += io.last_arc_size;
    }
    arc.close();
    let mut next_name = arc.file_name().to_string();
    next_volume_name(&mut next_name, !arc.new_numbering);
    let mut recovery_done = false;
    let mut old_scheme_tested = false;
    let mut failed_open = false;
    let (volume_pause, all_yes) = {
        let c = cmd.borrow();
        (c.volume_pause, c.all_yes)
    };
    if volume_pause && !crate::ui::ui_ask_next_volume(&next_name) {
        failed_open = true;
    }
    if crate::filefn::file_exist(&next_name) && crate::filefn::is_dir(crate::filefn::get_file_attr(&next_name)) {
        failed_open = true;
    }
    if !failed_open {
        while !arc.open(&next_name, 0) {
            if let Some(io) = data_io.as_deref_mut() {
                io.total_arc_size = 0;
            }
            if !old_scheme_tested {
                let mut alt = arc.file_name().to_string();
                next_volume_name(&mut alt, true);
                old_scheme_tested = true;
                if arc.open(&alt, 0) {
                    next_name = alt;
                    break;
                }
            }
            if !recovery_done {
                let name = arc.file_name().to_string();
                crate::recvol::rec_volumes_restore(&cmd, &name, true);
                recovery_done = true;
                continue;
            }
            if !volume_pause && !crate::filefn::is_removable(&next_name) {
                failed_open = true;
                break;
            }
            if all_yes || !crate::ui::ui_ask_next_volume(&next_name) {
                failed_open = true;
                break;
            }
        }
    }
    if failed_open {
        set_error_code(RARX_OPEN);
        ui_msg(UiMsg::MissingVol(next_name.clone()));
        let name = arc.file_name().to_string();
        arc.open(&name, 0);
        arc.seek(pos_before_close, SEEK_SET);
        return false;
    }
    if command == 'T' || command == 'X' || command == 'E' {
        crate::consio::mprintf(&wfmt!(if command == 'T' { MTestVol } else { MExtrVol }, arc.file_name()));
    }
    arc.check_arc(true);
    if arc.encrypted != prev_vol_encrypted {
        ui_msg(UiMsg::BadArchive(arc.file_name().to_string()));
        errhnd::exit(RARX_BADARC);
    }
    if split_header {
        arc.search_block(header_type);
    } else {
        arc.read_header();
    }
    if arc.get_header_type() == HEAD_FILE {
        arc.convert_attributes();
        let p = arc.next_block_pos - arc.file_head.pack_size;
        arc.seek(p, SEEK_SET);
    }
    if show_file_name && !cmd.borrow().disable_names {
        crate::consio::mprintf(&wfmt!(MExtrPoints, arc.file_head.file_name.as_str()));
        if !cmd.borrow().disable_percentage {
            crate::consio::mprintf("     ");
        }
    }
    if let Some(io) = data_io {
        if header_type == HEAD_ENDARC {
            io.unp_volume = false;
        } else {
            let hd = if use_sub { &arc.sub_head } else { &arc.file_head };
            io.unp_volume = hd.split_after;
            io.set_packed_size_to_read(hd.pack_size);
        }
        io.adjust_total_arc_size(arc);
        io.cur_unp_read = 0;
        let kind = if use_sub { arc.sub_head.file_hash.kind } else { arc.file_head.file_hash.kind };
        io.packed_data_hash.init(kind);
    }
    true
}
