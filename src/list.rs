// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! List archive contents.

use crate::archive::{Archive, RarFormat};
use crate::cmddata::{CmdRef, VOLSIZE_AUTO};
use crate::consio::mprintf;
use crate::hash::HashType;
use crate::headers::*;
use crate::loclang::*;
use crate::matchfn::MATCH_WILDSUBPATH;
use crate::pathfn::parse_version_file_name;
use crate::strfn::bin_to_hex;
use crate::ui::to_percent_unlim;
use crate::unicode::char_to_wide;
use crate::wfmt;

pub fn list_archive(cmd: &CmdRef) {
    let mut sum_pack: i64 = 0;
    let mut sum_unp: i64 = 0;
    let mut arc_count = 0u32;
    let mut sum_file_count = 0u32;
    let command = cmd.borrow().command.clone();
    let verbose = command.starts_with('V');
    let mut technical = false;
    let mut bare = false;
    let mut show_service = false;
    for ch in command.chars() {
        bare |= ch == 'B';
        technical |= ch == 'T';
        show_service |= ch == 'A';
    }
    loop {
        let arc_name = match cmd.borrow_mut().get_arc_name() {
            Some(n) => n,
            None => break,
        };
        {
            let mut c = cmd.borrow_mut();
            if c.manual_password {
                c.password_clean();
            }
        }
        let mut arc = Archive::new(cmd.clone());
        if !arc.w_open(&arc_name) {
            continue;
        }
        let mut file_matched = true;
        loop {
            let mut total_pack: i64 = 0;
            let mut total_unp: i64 = 0;
            let mut file_count = 0u32;
            if arc.is_archive(true) {
                let mut title_shown = false;
                if !bare {
                    arc.view_comment();
                    mprintf(&wfmt!("\n%s: %s", MListArchive, arc.file_name()));
                    mprintf(&wfmt!("\n%s: ", MListDetails));
                    let fmt = match arc.format {
                        RarFormat::Rar14 => "RAR 1.4",
                        RarFormat::Rar15 => "RAR 1.5",
                        _ => "RAR 5",
                    };
                    mprintf(fmt);
                    if arc.solid {
                        mprintf(&wfmt!(", %s", MListSolid));
                    }
                    if arc.sfx_size > 0 {
                        mprintf(&wfmt!(", %s", MListSFX));
                    }
                    if arc.volume {
                        if arc.format == RarFormat::Rar50 {
                            mprintf(", ");
                            mprintf(&wfmt!(MVolumeNumber, arc.vol_number + 1));
                        } else {
                            mprintf(&wfmt!(", %s", MListVolume));
                        }
                    }
                    if arc.protected {
                        mprintf(&wfmt!(", %s", MListRR));
                    }
                    if arc.locked {
                        mprintf(&wfmt!(", %s", MListLock));
                    }
                    if arc.encrypted {
                        mprintf(&wfmt!(", %s", MListEncHead));
                    }
                    if !arc.main_head.orig_name.is_empty() {
                        mprintf(&wfmt!("\n%s: %s", MOrigName, arc.main_head.orig_name.as_str()));
                    }
                    if arc.main_head.orig_time.is_set() {
                        let d = arc.main_head.orig_time.get_text(technical);
                        mprintf(&wfmt!("\n%s: %s", MOriginalTime, d));
                    }
                    mprintf("\n");
                }
                let mut vol_num_text = String::new();
                while arc.read_header() > 0 {
                    crate::errhnd::wait();
                    let ht = arc.get_header_type();
                    if ht == HEAD_ENDARC {
                        if arc.end_arc_head.store_vol_number && arc.format == RarFormat::Rar15 {
                            vol_num_text = wfmt!("%.10s %u", MListVolume, arc.vol_number + 1);
                        }
                        if technical && show_service {
                            mprintf(&wfmt!("\n%12s: %s", MListService, "EOF"));
                            if !vol_num_text.is_empty() {
                                mprintf(&wfmt!("\n%12s: %s", MListFlags, vol_num_text.as_str()));
                            }
                            mprintf("\n");
                        }
                        break;
                    }
                    match ht {
                        HEAD_FILE => {
                            file_matched = cmd.borrow().is_process_file(&arc.file_head, None, MATCH_WILDSUBPATH, None) != 0;
                            if file_matched {
                                let dn = cmd.borrow().disable_names;
                                let hd = arc.file_head.clone();
                                list_file_header(&mut arc, &hd, &mut title_shown, verbose, technical, bare, dn);
                                if !arc.file_head.split_before {
                                    total_unp += arc.file_head.unp_size;
                                    file_count += 1;
                                }
                                total_pack += arc.file_head.pack_size;
                            }
                        }
                        HEAD_SERVICE => {
                            let dn = cmd.borrow().disable_names;
                            if !arc.sub_head.sub_block || dn {
                                file_matched = cmd.borrow().is_process_file(&arc.sub_head, None, MATCH_WILDSUBPATH, None) != 0;
                            }
                            if file_matched && (technical || show_service) {
                                let hd = arc.sub_head.clone();
                                list_file_header(&mut arc, &hd, &mut title_shown, verbose, technical, bare, false);
                            }
                        }
                        _ => {}
                    }
                    arc.seek_to_next();
                }
                if !bare && !technical {
                    if title_shown {
                        let unp = total_unp.to_string();
                        let pack = total_pack.to_string();
                        if verbose {
                            mprintf("\n----------- ---------- ---------- ----- ---------- -----  --------  ----");
                            mprintf(&wfmt!(
                                "\n%22s %10s %3d%%  %-27s %u",
                                unp,
                                pack,
                                to_percent_unlim(total_pack, total_unp),
                                vol_num_text.as_str(),
                                file_count
                            ));
                        } else {
                            mprintf("\n----------- ----------  ---------- -----  ----");
                            mprintf(&wfmt!("\n%22s  %-16s  %u", unp, vol_num_text.as_str(), file_count));
                        }
                        sum_file_count += file_count;
                        sum_unp += total_unp;
                        sum_pack += total_pack;
                        mprintf("\n");
                    } else {
                        mprintf(MListNoFiles);
                    }
                }
                arc_count += 1;
                let vol_size = cmd.borrow().vol_size;
                let c0 = cmd.borrow().cmd_char();
                if vol_size == VOLSIZE_AUTO
                    && (arc.file_head.split_after || arc.get_header_type() == HEAD_ENDARC && arc.end_arc_head.next_volume)
                    && crate::volume::merge_archive(&mut arc, None, false, c0)
                {
                    arc.seek(0, crate::file::SEEK_SET);
                } else {
                    break;
                }
            } else {
                if cmd.borrow().arc_names.items_count() < 2 && !bare {
                    mprintf(&wfmt!(MNotRAR, arc.file_name()));
                }
                break;
            }
        }
    }
    {
        let mut c = cmd.borrow_mut();
        if c.manual_password {
            c.password_clean();
        }
    }
    if arc_count > 1 && !bare && !technical {
        let unp = sum_unp.to_string();
        let pack = sum_pack.to_string();
        if verbose {
            mprintf(&wfmt!("%21s %9s %3d%% %28s %u", unp, pack, to_percent_unlim(sum_pack, sum_unp), "", sum_file_count));
        } else {
            mprintf(&wfmt!("%21s %18s %lu", unp, "", sum_file_count));
        }
    }
}

fn list_file_header(arc: &mut Archive, hd: &FileHeader, title_shown: &mut bool, verbose: bool, technical: bool, bare: bool, disable_names: bool) {
    if !*title_shown && !technical && !bare {
        if verbose {
            mprintf(&wfmt!("\n%s", MListTitleV));
            if !disable_names {
                mprintf("\n----------- ---------- ---------- ----- ---------- -----  --------  ----");
            }
        } else {
            mprintf(&wfmt!("\n%s", MListTitleL));
            if !disable_names {
                mprintf("\n----------- ----------  ---------- -----  ----");
            }
        }
        *title_shown = true;
    }
    if disable_names {
        return;
    }
    let name = hd.file_name.as_str();
    let format = arc.format;
    let file_block = hd.base.header_type == HEAD_FILE;
    let mut stream_name = String::new();
    if !file_block && arc.sub_head.cmp_name(SUBHEAD_TYPE_STREAM) {
        stream_name = crate::extinfo::get_stream_name_ntfs(arc);
    }
    if bare {
        mprintf(&wfmt!("%s%s\n", name, stream_name.as_str()));
        return;
    }
    let unp_size_text = if hd.unp_size == INT64NDF { "?".to_string() } else { hd.unp_size.to_string() };
    let pack_size_text = hd.pack_size.to_string();
    let attr_str = if hd.base.header_type == HEAD_SERVICE {
        format!("{}B", if hd.inherited { 'I' } else { '.' })
    } else {
        list_file_attr(hd.file_attr, hd.hs_type)
    };
    let ratio_str = if hd.split_before && hd.split_after {
        "<->".to_string()
    } else if hd.split_before {
        "<--".to_string()
    } else if hd.split_after {
        "-->".to_string()
    } else {
        format!("{}%", to_percent_unlim(hd.pack_size, hd.unp_size) as u32)
    };
    let date_str = if hd.mtime.is_set() { hd.mtime.get_text(technical) } else { "                ".to_string() };
    if technical {
        mprintf(&wfmt!("\n%12s: %s", MListName, name));
        if !stream_name.is_empty() {
            mprintf(&wfmt!("\n%12s: %s", MListType, MListStream));
            mprintf(&wfmt!("\n%12s: %s", MListTarget, stream_name.as_str()));
        } else {
            let mut t = if file_block {
                if hd.dir {
                    MListDir
                } else {
                    MListFile
                }
            } else {
                MListService
            };
            match hd.redir_type {
                FsRedir::UnixSymlink => t = MListUSymlink,
                FsRedir::WinSymlink => t = MListWSymlink,
                FsRedir::Junction => t = MListJunction,
                FsRedir::Hardlink => t = MListHardlink,
                FsRedir::FileCopy => t = MListCopy,
                _ => {}
            }
            mprintf(&wfmt!("\n%12s: %s", MListType, t));
            if hd.redir_type != FsRedir::None {
                if format == RarFormat::Rar15 {
                    let target = if arc.file_head.encrypted {
                        "*<-?->".to_string()
                    } else {
                        let n = (hd.pack_size.max(0) as usize).min(0x10000);
                        let mut buf = vec![0u8; n];
                        arc.read(&mut buf);
                        char_to_wide(&buf)
                    };
                    mprintf(&wfmt!("\n%12s: %s", MListTarget, target));
                } else {
                    mprintf(&wfmt!("\n%12s: %s", MListTarget, hd.redir_name.as_str()));
                }
            }
        }
        if !hd.dir {
            mprintf(&wfmt!("\n%12s: %s", MListSize, unp_size_text.as_str()));
            mprintf(&wfmt!("\n%12s: %s", MListPacked, pack_size_text.as_str()));
            mprintf(&wfmt!("\n%12s: %s", MListRatio, ratio_str.as_str()));
            if !file_block && arc.sub_head.cmp_name(SUBHEAD_TYPE_RR) {
                let rp = arc.get_recovery_percent();
                if rp > 0 {
                    mprintf(&wfmt!("\n%12s: %u%%", "RR%", rp));
                }
            }
        }
        let win_titles = cfg!(windows);
        if hd.mtime.is_set() {
            mprintf(&wfmt!("\n%12s: %s", if win_titles { MListModified } else { MListMtime }, date_str.as_str()));
        }
        if hd.ctime.is_set() {
            let d = hd.ctime.get_text(true);
            mprintf(&wfmt!("\n%12s: %s", if win_titles { MListCreated } else { MListCtime }, d));
        }
        if hd.atime.is_set() {
            let d = hd.atime.get_text(true);
            mprintf(&wfmt!("\n%12s: %s", if win_titles { MListAccessed } else { MListAtime }, d));
        }
        mprintf(&wfmt!("\n%12s: %s", MListAttr, attr_str.as_str()));
        if hd.file_hash.kind == HashType::Crc32 {
            let t = if hd.use_hash_key {
                "CRC32 MAC"
            } else if hd.split_after {
                "Pack-CRC32"
            } else {
                "CRC32"
            };
            mprintf(&wfmt!("\n%12s: %8.8X", t, hd.file_hash.crc32));
        }
        if hd.file_hash.kind == HashType::Blake2 {
            let t = if hd.use_hash_key {
                "BLAKE2 MAC"
            } else if hd.split_after {
                "Pack-BLAKE2"
            } else {
                "BLAKE2"
            };
            mprintf(&wfmt!("\n%12s: %s", t, bin_to_hex(&hd.file_hash.digest)));
        }
        let mut host_os = "";
        if format == RarFormat::Rar50 && hd.hs_type != HostSystemType::Unknown {
            host_os = if hd.hs_type == HostSystemType::Windows { "Windows" } else { "Unix" };
        }
        if format == RarFormat::Rar15 {
            const RAR_OS: [&str; 10] = ["DOS", "OS/2", "Windows", "Unix", "Mac OS", "BeOS", "WinCE", "", "", ""];
            if (hd.host_os as usize) < RAR_OS.len() {
                host_os = RAR_OS[hd.host_os as usize];
            }
        }
        if !host_os.is_empty() {
            mprintf(&wfmt!("\n%12s: %s", MListHostOS, host_os));
        }
        let mut win_size = String::new();
        if !hd.dir {
            if hd.win_size.is_multiple_of(1073741824) {
                win_size = format!(" -md={}g", hd.win_size / 1073741824);
            } else if hd.win_size.is_multiple_of(1048576) {
                win_size = format!(" -md={}m", hd.win_size / 1048576);
            } else if hd.win_size >= 1024 {
                win_size = format!(" -md={}k", hd.win_size / 1024);
            } else {
                win_size = " -md=?".to_string();
            }
        }
        mprintf(&wfmt!(
            "\n%12s: RAR %s(v%d) -m%d%s",
            MListCompInfo,
            if format == RarFormat::Rar15 { "1.5" } else { "5.0" },
            if hd.unp_ver == VER_UNKNOWN { 0 } else { hd.unp_ver },
            hd.method,
            win_size
        ));
        if hd.solid || hd.encrypted {
            mprintf(&wfmt!("\n%12s: ", MListFlags));
            if hd.solid {
                mprintf(&wfmt!("%s ", MListSolid));
            }
            if hd.encrypted {
                mprintf(&wfmt!("%s ", MListEnc));
            }
        }
        if hd.version {
            let mut n = hd.file_name.clone();
            let v = parse_version_file_name(&mut n, false);
            if v != 0 {
                mprintf(&wfmt!("\n%12s: %u", MListFileVer, v));
            }
        }
        if hd.unix_owner_set {
            mprintf(&wfmt!("\n%12s: ", "Unix owner"));
            if !hd.unix_owner_name.is_empty() {
                mprintf(&char_to_wide(&hd.unix_owner_name));
            } else if hd.unix_owner_numeric {
                mprintf(&wfmt!("#%d", hd.unix_owner_id as i32));
            }
            mprintf(":");
            if !hd.unix_group_name.is_empty() {
                mprintf(&char_to_wide(&hd.unix_group_name));
            } else if hd.unix_group_numeric {
                mprintf(&wfmt!("#%d", hd.unix_group_id as i32));
            }
        }
        mprintf("\n");
        return;
    }
    mprintf(&wfmt!("\n%c%10s %10s ", if hd.encrypted { '*' } else { ' ' }, attr_str.as_str(), unp_size_text.as_str()));
    if verbose {
        mprintf(&wfmt!("%10s %4s ", pack_size_text.as_str(), ratio_str.as_str()));
    }
    mprintf(&wfmt!(" %s  ", date_str.as_str()));
    if verbose {
        if hd.file_hash.kind == HashType::Crc32 {
            mprintf(&wfmt!("%8.8X  ", hd.file_hash.crc32));
        } else if hd.file_hash.kind == HashType::Blake2 {
            let s = &hd.file_hash.digest;
            mprintf(&wfmt!("%02x%02x..%02x  ", s[0], s[1], s[31]));
        } else {
            mprintf("          ");
        }
    }
    mprintf(name);
    if !stream_name.is_empty() {
        mprintf(&stream_name);
    }
}

fn list_file_attr(a: u32, host: HostSystemType) -> String {
    match host {
        HostSystemType::Windows => {
            let f = |m: u32, c: char| if a & m != 0 { c } else { '.' };
            [f(0x2000, 'I'), f(0x0800, 'C'), f(0x0020, 'A'), f(0x0010, 'D'), f(0x0004, 'S'), f(0x0002, 'H'), f(0x0001, 'R')]
                .iter()
                .collect()
        }
        HostSystemType::Unix => {
            let t = match a & 0xF000 {
                0x4000 => 'd',
                0xA000 => 'l',
                _ => '-',
            };
            let b = |m: u32, c: char| if a & m != 0 { c } else { '-' };
            let x = |m: u32, s: u32, lo: char, up: char| {
                if a & m != 0 {
                    if a & s != 0 {
                        lo
                    } else {
                        'x'
                    }
                } else if a & s != 0 {
                    up
                } else {
                    '-'
                }
            };
            let other_x = if a & 0x0001 != 0 {
                if a & 0x200 != 0 {
                    't'
                } else {
                    'x'
                }
            } else {
                '-'
            };
            [
                t,
                b(0x0100, 'r'),
                b(0x0080, 'w'),
                x(0x0040, 0x0800, 's', 'S'),
                b(0x0020, 'r'),
                b(0x0010, 'w'),
                x(0x0008, 0x0400, 's', 'S'),
                b(0x0004, 'r'),
                b(0x0002, 'w'),
                other_x,
            ]
            .iter()
            .collect()
        }
        HostSystemType::Unknown => "?".to_string(),
    }
}
