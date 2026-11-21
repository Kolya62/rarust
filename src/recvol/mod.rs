// SPDX-License-Identifier: GPL-3.0-or-later

//! Recovery volumes (.rev): testing them and rebuilding missing or
//! damaged volumes of RAR 3.x and RAR 5.0 volume sets.
//!
//! RAR 3.x .rev files carry no header. Old style names are
//! "name_N_R_T.rev" (recovery number, recovery count, data volume count);
//! new style files end with 3 bytes (count, recovery count, number, each
//! minus one) and the CRC32 of everything before it.
//!
//! RAR 5.0 .rev files start with "Rar!\x1aRev", the header CRC32 and
//! size, then: version u8 (1), data count u16, recovery count u16, this
//! volume's number u16, CRC32 of this volume's data, and (in every file)
//! size u64 and CRC32 of each data volume.

mod gf;

use crate::archive::{Archive, RarFormat};
use crate::cmddata::CmdRef;
use crate::consio::mprintf;
use crate::errhnd::{self, *};
use crate::file::{File, SEEK_END, SEEK_SET};
use crate::filcreat::file_create;
use crate::filefn::*;
use crate::find::{FindData, FindFile};
use crate::hash::{DataHash, HashType};
use crate::headers::HEAD_ENDARC;
use crate::loclang::*;
use crate::pathfn::*;
use crate::strfn::atoiw;
use crate::ui::*;
use crate::wfmt;

const REV5_SIGN: &[u8; 8] = b"Rar!\x1aRev";
/// Memory for one pass over all volumes.
const BUFFER_SIZE: usize = 0x4000000;

/// A volume opened as a plain file or through `Archive`.
enum Vol {
    File(File),
    Arc(Box<Archive>),
}

impl Vol {
    fn file(&mut self) -> &mut File {
        match self {
            Vol::File(f) => f,
            Vol::Arc(a) => &mut a.file,
        }
    }
    fn read(&mut self, b: &mut [u8]) -> usize {
        match self {
            Vol::File(f) => f.read(b),
            Vol::Arc(a) => a.read(b),
        }
        .max(0) as usize
    }
    fn write(&mut self, b: &[u8]) {
        self.file().write(b);
    }
}

/// CRC32 of `size` bytes (or the rest of the file) from the start or
/// from the current position; the position is restored.
fn file_crc(f: &mut File, size: Option<i64>, from_current: bool, progress: bool) -> u32 {
    let saved = f.tell();
    let total = size.unwrap_or_else(|| f.file_length());
    if !from_current {
        f.seek(0, SEEK_SET);
    }
    let mut buf = vec![0u8; 0x100000];
    let mut hash = DataHash::new(HashType::Crc32);
    let mut left = size;
    let mut done = 0i64;
    for block in 1u64.. {
        let want = left.map_or(buf.len(), |l| (l.max(0) as usize).min(buf.len()));
        let n = f.read(&mut buf[..want]);
        if n <= 0 {
            break;
        }
        done += n as i64;
        if progress && block % 16 == 0 {
            ui_extract_progress(done, total, 0, 0);
        }
        hash.update(&buf[..n as usize]);
        if let Some(l) = left.as_mut() {
            *l -= n as i64;
        }
    }
    f.seek(saved, SEEK_SET);
    hash.crc32()
}

fn show_percent(done: i64, total: i64) {
    mprintf(&wfmt!("\x08\x08\x08\x08%3d%%", to_percent(done, total)));
}

fn is_rev5(f: &mut impl FnMut(&mut [u8]) -> i32) -> bool {
    let mut sign = [0u8; 8];
    f(&mut sign) == 8 && &sign == REV5_SIGN
}

/// Rebuilds missing volumes of the set `name` belongs to (a volume or a
/// .rev file).
pub fn rec_volumes_restore(cmd: &CmdRef, name: &str, silent: bool) -> bool {
    let mut arc = Archive::new(cmd.clone());
    if !arc.open(name, 0) {
        if !silent {
            errhnd::open_error_msg("", name);
        }
        return false;
    }
    let rev5 = if arc.is_archive(true) {
        arc.format == RarFormat::Rar50
    } else {
        arc.seek(0, SEEK_SET);
        is_rev5(&mut |b| arc.read(b))
    };
    arc.close();
    if rev5 {
        Rev5::default().restore(cmd, name, silent)
    } else {
        restore3(cmd, name, silent)
    }
}

/// Checks the recovery volumes of an archive, or of the .rev file `name`.
pub fn rec_volumes_test(cmd: &CmdRef, arc: Option<&mut Archive>, name: &str) {
    let rev_name = match arc {
        None => name.to_string(),
        Some(a) => match first_rev_name(name, a.new_numbering) {
            Some(n) => n,
            None => return,
        },
    };
    let mut rev = File::new();
    if !rev.open(&rev_name, 0) {
        errhnd::open_error_msg("", &rev_name);
        return;
    }
    mprintf("\n");
    let five = is_rev5(&mut |b| rev.read(b));
    rev.close();
    if five {
        Rev5::default().test(cmd, &rev_name);
    } else {
        test3(cmd, &rev_name);
    }
}

/// The .rev file numbered 1 (with any leading zeros) of the set.
fn first_rev_name(vol: &str, new_numbering: bool) -> Option<String> {
    let (first, num_start) = vol_name_to_first_name(vol, new_numbering);
    let mut mask: String = first.chars().take(num_start).collect();
    mask.push_str("*.rev");
    let mut find = FindFile::new();
    find.set_mask(&mask);
    let mut fd = FindData::default();
    while find.next(&mut fd, false) {
        let n = chars(&fd.name);
        let pos = get_vol_num_pos(&n);
        if at(&n, pos) != '1' {
            continue;
        }
        // All digits before the final 1 must be zeros.
        let leading = n[..pos].iter().rev().take_while(|c| c.is_ascii_digit());
        if leading.clone().all(|&c| c == '0') {
            return Some(fd.name.clone());
        }
    }
    None
}

/// Checks the CRC of each .rev file in the sequence starting at `name`.
fn test_rev_files(name: &str, mut check: impl FnMut(&mut File) -> bool) {
    let mut vol = name.to_string();
    while file_exist(&vol) {
        let mut f = File::new();
        if !f.open(&vol, 0) {
            errhnd::open_error_msg("", &vol);
            next_volume_name(&mut vol, false);
            continue;
        }
        mprintf(&wfmt!(MExtrTestFile, vol.as_str()));
        mprintf("     ");
        if check(&mut f) {
            mprintf(&wfmt!("%s%s ", "\x08\x08\x08\x08\x08 ", MOk));
        } else {
            ui_msg(UiMsg::Checksum(vol.clone(), vol.clone()));
            set_error_code(RARX_CRC);
        }
        next_volume_name(&mut vol, false);
    }
}

// RAR 3.x.

/// New style names have at most one "_digits" group before the
/// extension ("name.part1_3.rev" style names are old).
fn is_new_style_rev(name: &str) -> bool {
    let Some(p) = get_ext_pos(name).filter(|&p| p > 0) else { return true };
    let v: Vec<char> = name[..p].chars().collect();
    let mut groups = 0;
    let mut i = v.len() - 1;
    while i > 0 {
        if !v[i].is_ascii_digit() {
            if v[i] == '_' && v[i - 1].is_ascii_digit() {
                groups += 1;
            } else {
                break;
            }
        }
        i -= 1;
    }
    groups < 2
}

/// Recovery number, recovery count and data count of a RAR 3.x .rev
/// file, or None if it is invalid. New style values come from the file
/// tail, old style from the name.
fn rev3_numbers(name: &str, new_style: bool, base_len: usize) -> Option<[i32; 3]> {
    let mut p = [0i32; 3];
    if new_style {
        let mut f = File::new();
        f.t_open(name);
        f.seek(0, SEEK_END);
        let len = f.tell();
        if len < 7 {
            return None;
        }
        f.seek(len - 7, SEEK_SET);
        for i in (0..3).rev() {
            p[i] = f.get_byte() as i32 + 1;
        }
        let crc = (0..4).fold(0u32, |c, i| c | (f.get_byte() as u32) << (i * 8));
        if crc != file_crc(&mut f, Some(len - 4), false, false) {
            ui_msg(UiMsg::MsgChecksum(name.to_string()));
            return None;
        }
    } else {
        // "..._N_R_T.rev": read the three numbers from the end.
        let dot = get_ext_pos(name)?;
        let v: Vec<char> = name.chars().collect();
        let mut d = name[..dot].chars().count();
        for x in p.iter_mut() {
            while d > 0 {
                d -= 1;
                if !(v[d].is_ascii_digit() && d >= base_len) {
                    break;
                }
            }
            *x = atoiw(&v[d + 1..].iter().collect::<String>()) as i32;
            if *x == 0 || *x > 255 {
                return None;
            }
        }
    }
    Some(p)
}

/// A volume (or its replacement) is valid if its end of archive header
/// has a matching data CRC, when it has one.
fn volume3_valid(arc: &mut Archive, name: &str) -> bool {
    if !arc.is_archive(false) {
        return false;
    }
    while arc.read_header() != 0 {
        if arc.get_header_type() == HEAD_ENDARC {
            ui_msg(UiMsg::MsgString(name.to_string()));
            if arc.end_arc_head.data_crc {
                let end = arc.cur_block_pos;
                if arc.end_arc_head.arc_data_crc != file_crc(&mut arc.file, Some(end), false, false) {
                    ui_msg(UiMsg::MsgChecksum(name.to_string()));
                    return false;
                }
            }
            break;
        }
        arc.seek_to_next();
    }
    true
}

fn restore3(cmd: &CmdRef, name: &str, silent: bool) -> bool {
    let mut arc_name = name.to_string();
    let named_rev = cmp_ext(&arc_name, "rev");
    let mut new_style = false;
    if named_rev {
        // Find a volume of the set from the .rev name.
        new_style = is_new_style_rev(&arc_name);
        let v = chars(&arc_name);
        let mut end = arc_name[..get_ext_pos(&arc_name).unwrap()].chars().count();
        while end > 1 && (v[end - 1].is_ascii_digit() || v[end - 1] == '_') {
            end -= 1;
        }
        arc_name = v[..end].iter().collect::<String>() + "*.*";
        let mut find = FindFile::new();
        find.set_mask(&arc_name);
        let mut fd = FindData::default();
        while find.next(&mut fd, false) {
            let mut a = Archive::new(cmd.clone());
            if a.w_open(&fd.name) && a.is_archive(true) {
                arc_name = fd.name.clone();
                break;
            }
        }
    }
    let mut arc = Archive::new(cmd.clone());
    if !arc.w_check_open(&arc_name) || !arc.volume {
        return false;
    }
    let new_numbering = arc.new_numbering;
    arc.close();
    let (first, base_len) = vol_name_to_first_name(&arc_name, new_numbering);
    arc_name = first;
    if base_len == 0 {
        return false;
    }
    let rev_mask = chars(&arc_name)[..base_len].iter().collect::<String>() + "*.rev";

    // Collect recovery volumes; slot = data count + recovery number - 1.
    let mut vols: Vec<Option<Vol>> = (0..256).map(|_| None).collect();
    let (mut data_count, mut rec_count, mut found) = (0i32, 0i32, 0u32);
    let mut rev_size = 0i64;
    let mut prev_name = String::new();
    let mut checksum_msg = false;
    let mut find = FindFile::new();
    find.set_mask(&rev_mask);
    let mut fd = FindData::default();
    while find.next(&mut fd, false) {
        let cur = fd.name.clone();
        if !named_rev && !new_style {
            // Two '_' after the last dot before the extension mean old
            // style (the first character of the name is not checked).
            new_style = true;
            if let Some(dp) = get_ext_pos(&cur) {
                let v: Vec<char> = cur[..dp].chars().collect();
                let tail = v[1.min(v.len())..].iter().rev().take_while(|&&c| c != '.');
                if tail.filter(|&&c| c == '_').count() == 2 {
                    new_style = false;
                }
            }
        }
        if new_style {
            if !checksum_msg {
                ui_msg(UiMsg::RecVolCalcChecksum);
                checksum_msg = true;
            }
            ui_msg(UiMsg::MsgString(cur.clone()));
        }
        let Some(p) = rev3_numbers(&cur, new_style, base_len) else { continue };
        if p[0] <= 0 || p[1] <= 0 || p[2] <= 0 || p[1] + p[2] > 255 || p[0] + p[2] - 1 > 255 {
            continue;
        }
        if (rec_count != 0 && rec_count != p[1]) || (data_count != 0 && data_count != p[2]) {
            ui_msg(UiMsg::RecVolDiffSets(cur, prev_name));
            return false;
        }
        rec_count = p[1];
        data_count = p[2];
        prev_name = cur.clone();
        let slot = (data_count + p[0] - 1) as usize;
        if slot >= 256 || vols[slot].is_some() {
            continue;
        }
        let mut f = File::new();
        f.t_open(&cur);
        if rev_size == 0 {
            rev_size = f.file_length();
        }
        vols[slot] = Some(Vol::File(f));
        found += 1;
    }
    if !silent || found != 0 {
        ui_msg(UiMsg::RecVolFound(found));
    }
    if found == 0 {
        return false;
    }

    // Open the data volumes; missing or damaged ones are created anew.
    let mut rebuild = [false; 256];
    let mut last_vol = String::new();
    let mut missing = 0u32;
    for i in 0..data_count as usize {
        let mut a = Box::new(Archive::new(cmd.clone()));
        let mut ok = file_exist(&arc_name);
        if ok {
            a.file.t_open(&arc_name);
            ok = volume3_valid(&mut a, &arc_name);
            if !ok {
                a.close();
                let bad = format!("{arc_name}.bad");
                ui_msg(UiMsg::MsgBadArchive(arc_name.clone()));
                ui_msg(UiMsg::MsgRenaming(arc_name.clone(), bad.clone()));
                rename_file(&arc_name, &bad);
            }
            a.seek(0, SEEK_SET);
        }
        if !ok {
            if !a.file.create(&arc_name, crate::file::FMF_WRITE | crate::file::FMF_SHAREREAD) {
                ui_msg(UiMsg::Reconstructing);
                errhnd::create_error_msg("", &arc_name);
                return false;
            }
            rebuild[i] = true;
            missing += 1;
            if i as i32 == data_count - 1 {
                last_vol = arc_name.clone();
            }
            ui_msg(UiMsg::MsgMissingVol(arc_name.clone()));
        }
        vols[i] = Some(Vol::Arc(a));
        next_volume_name(&mut arc_name, !new_numbering);
    }
    ui_msg(UiMsg::RecVolMissing(missing));
    if missing == 0 {
        ui_msg(UiMsg::RecVolAllExist);
        return false;
    }
    if missing > found {
        ui_msg(UiMsg::RecVolCannotFix);
        return false;
    }
    ui_msg(UiMsg::MsgReconstructing);

    let total = (data_count + rec_count) as usize;
    let erased: Vec<usize> = (0..total).filter(|&i| rebuild[i] || vols[i].is_none()).collect();
    let rs = gf::Rs8::new(total, rec_count as usize, &erased);
    let block = BUFFER_SIZE / total;
    let mut buf = vec![0u8; block * total];
    let mut word = vec![0u8; total];
    let (mut done, mut last_percent) = (0i64, -1);
    let quiet = cmd.borrow().disable_percentage;
    mprintf("     ");
    loop {
        crate::errhnd::wait();
        let mut longest = 0;
        for (i, area) in buf.chunks_mut(block).enumerate() {
            let n = match &mut vols[i] {
                Some(v) if !rebuild[i] => v.read(area),
                _ => 0,
            };
            area[n..].fill(0);
            longest = longest.max(n);
        }
        if longest == 0 {
            break;
        }
        let percent = to_percent(done, rev_size);
        if !quiet && percent != last_percent {
            show_percent(done, rev_size);
            last_percent = percent;
        }
        done += longest as i64;
        for pos in 0..longest {
            for (i, w) in word.iter_mut().enumerate() {
                *w = buf[i * block + pos];
            }
            rs.decode(&mut word);
            for &e in &erased {
                buf[e * block + pos] = word[e];
            }
        }
        for i in 0..data_count as usize {
            if rebuild[i] {
                let data = buf[i * block..i * block + longest].to_vec();
                vols[i].as_mut().unwrap().write(&data);
            }
        }
    }
    for (i, v) in vols.iter_mut().enumerate().take(total) {
        if let Some(mut v) = v.take() {
            if new_style && rebuild[i] {
                // Rebuilt volumes end with the recovery data tail; zero it.
                let f = v.file();
                let len = f.tell();
                f.seek(len - 7, SEEK_SET);
                f.write(&[0u8; 7]);
            }
            v.file().keep();
            v.file().close();
        }
    }
    if !last_vol.is_empty() {
        // The rebuilt last volume is padded to the recovery size: drop
        // the zeros after its end of archive header.
        let mut a = Archive::new(cmd.clone());
        if a.open(&last_vol, crate::file::FMF_UPDATE) && a.is_archive(true) && a.search_block(HEAD_ENDARC) != 0 {
            let end = a.next_block_pos;
            a.seek(end, SEEK_SET);
            let mut tail = vec![0u8; 8192];
            let n = a.read(&mut tail).max(0) as usize;
            if tail[..n].iter().all(|&b| b == 0) {
                a.seek(end, SEEK_SET);
                a.file.truncate();
            }
        }
    }
    if !quiet {
        mprintf("\x08\x08\x08\x08100%");
    }
    if !silent && !cmd.borrow().disable_done {
        mprintf(MDone);
    }
    true
}

fn test3(cmd: &CmdRef, name: &str) {
    if !is_new_style_rev(name) {
        errhnd::unknown_method_msg(name, name);
        return;
    }
    let quiet = cmd.borrow().disable_percentage;
    test_rev_files(name, |f| {
        f.seek(0, SEEK_END);
        let len = f.tell();
        f.seek(len - 4, SEEK_SET);
        let crc = (0..4).fold(0u32, |c, i| c | (f.get_byte() as u32) << (i * 8));
        crc == file_crc(f, Some(len - 4), false, !quiet)
    });
}

// RAR 5.0.

#[derive(Default)]
struct Item {
    vol: Option<Vol>,
    name: String,
    crc: u32,
    size: u64,
    /// Created by the rebuild.
    new: bool,
    valid: bool,
}

#[derive(Default)]
struct Rev5 {
    items: Vec<Item>,
    data_count: u32,
    rec_count: u32,
}

impl Rev5 {
    /// Reads a .rev header; returns this volume's number (0 if invalid).
    /// The first file also gives the sizes and CRCs of the data volumes.
    fn read_header(&mut self, f: &mut File, first: bool) -> u32 {
        let mut head = [0u8; 16];
        if f.read(&mut head) != 16 || &head[..8] != REV5_SIGN {
            return 0;
        }
        let size = u32::from_le_bytes(head[12..16].try_into().unwrap()) as usize;
        if size > 0x100000 || size <= 5 {
            return 0;
        }
        let mut h = vec![0u8; size];
        if f.read(&mut h) != size as i32 {
            return 0;
        }
        let crc = crate::hash::crc32::crc32(crate::hash::crc32::crc32(!0, &head[12..16]), &h) ^ !0;
        if crc != u32::from_le_bytes(head[8..12].try_into().unwrap()) {
            return 0;
        }
        let mut c = crate::rar4hdr::Cursor::new(&h, 0);
        if c.u8() != 1 {
            return 0;
        }
        let (dc, rc) = (c.u16() as u32, c.u16() as u32);
        if !first && (dc != self.data_count || rc != self.rec_count) {
            return 0;
        }
        self.data_count = dc;
        self.rec_count = rc;
        let total = dc + rc;
        let num = c.u16() as u32;
        if num >= total || total > 65535 {
            return 0;
        }
        let own_crc = c.u32();
        if first {
            self.items.resize_with(total as usize, Default::default);
            for it in &mut self.items[..dc as usize] {
                it.size = c.u32() as u64 | (c.u32() as u64) << 32;
                it.crc = c.u32();
            }
        }
        if let Some(it) = self.items.get_mut(num as usize) {
            it.crc = own_crc;
        }
        num
    }

    fn restore(&mut self, cmd: &CmdRef, name: &str, silent: bool) -> bool {
        let v = chars(name);
        let mut num_start = get_vol_num_pos(&v);
        while num_start > 0 && v[num_start - 1].is_ascii_digit() {
            num_start -= 1;
        }
        if num_start <= get_name_pos_c(&v) {
            return false;
        }
        let mask = v[..num_start].iter().collect::<String>() + "*.*";
        let mut first_vol = String::new();
        let mut longest_rev = String::new();
        let mut rev_size = 0i64;
        let mut found = 0u32;
        let mut find = FindFile::new();
        find.set_mask(&mask);
        let mut fd = FindData::default();
        while find.next(&mut fd, false) {
            crate::errhnd::wait();
            let mut vol = Box::new(Archive::new(cmd.clone()));
            if fd.is_dir || !vol.w_open(&fd.name) {
                continue;
            }
            let slot = if cmp_ext(&fd.name, "rev") {
                let n = self.read_header(&mut vol.file, found == 0);
                if n == 0 {
                    continue;
                }
                if found == 0 {
                    rev_size = vol.file.file_length();
                }
                found += 1;
                if fd.name.len() > longest_rev.len() {
                    longest_rev = fd.name.clone();
                }
                n as usize
            } else if vol.is_archive(true) && (vol.sfx_size > 0 || cmp_ext(&fd.name, "rar")) {
                if !vol.volume && !vol.broken_header {
                    return false;
                }
                let n = vol.file_name().to_string();
                vol.open(&n, 0);
                vol.seek(0, SEEK_SET);
                // Volume number: the digits ending at the number position.
                let nv = chars(&fd.name);
                let end = get_vol_num_pos(&nv) + 1;
                let digits = nv[..end].iter().rev().take_while(|c| c.is_ascii_digit());
                let num = digits.enumerate().fold(0u64, |acc, (k, &c)| acc + (c as u64 - '0' as u64) * 10u64.pow(k as u32));
                if num == 0 || num > 65535 {
                    continue;
                }
                if num as usize > self.items.len() {
                    self.items.resize_with(num as usize, Default::default);
                }
                if first_vol.is_empty() {
                    first_vol = vol_name_to_first_name(&fd.name, true).0;
                }
                num as usize - 1
            } else {
                continue;
            };
            if let Some(it) = self.items.get_mut(slot) {
                it.vol = Some(Vol::Arc(vol));
                it.new = false;
                it.name = fd.name.clone();
            }
        }
        if !silent || found != 0 {
            ui_msg(UiMsg::RecVolFound(found));
        }
        if found == 0 {
            return false;
        }
        if first_vol.is_empty() {
            set_ext(&mut longest_rev, "rar");
            first_vol = vol_name_to_first_name(&longest_rev, true).0;
        }
        ui_msg(UiMsg::RecVolCalcChecksum);
        let dc = self.data_count as usize;
        let tc = dc + self.rec_count as usize;
        if self.items.len() < tc {
            self.items.resize_with(tc, Default::default);
        }
        let mut missing = 0u32;
        for (i, it) in self.items.iter_mut().enumerate().take(tc) {
            if let Some(v) = it.vol.as_mut() {
                ui_msg(UiMsg::MsgString(it.name.clone()));
                it.valid = file_crc(v.file(), None, true, false) == it.crc;
                if !it.valid {
                    ui_msg(UiMsg::MsgChecksum(it.name.clone()));
                    if i >= dc {
                        it.vol = None;
                        found -= 1;
                    }
                }
            }
            if i < dc && !(it.vol.is_some() && it.valid) {
                missing += 1;
            }
        }
        ui_msg(UiMsg::RecVolMissing(missing));
        if missing == 0 {
            ui_msg(UiMsg::RecVolAllExist);
            return false;
        }
        if missing > found {
            ui_msg(UiMsg::RecVolCannotFix);
            return false;
        }
        ui_msg(UiMsg::MsgReconstructing);

        // Damaged volumes are renamed; missing ones are created.
        let mut max_size = 0u64;
        for it in &mut self.items[..dc] {
            max_size = max_size.max(it.size);
            if it.vol.is_some() && !it.valid {
                it.vol = None;
                let bad = format!("{}.bad", it.name);
                ui_msg(UiMsg::MsgBadArchive(it.name.clone()));
                ui_msg(UiMsg::MsgRenaming(it.name.clone(), bad.clone()));
                rename_file(&it.name, &bad);
            }
            it.new = it.vol.is_none();
            if it.new {
                it.name = first_vol.clone();
                ui_msg(UiMsg::Creating(it.name.clone()));
                let mut f = File::new();
                let (ok, rejected) = file_create(&mut cmd.borrow_mut(), Some(&mut f), &mut it.name, None, None, 0);
                if !ok {
                    if !rejected {
                        errhnd::create_error_msg("", &it.name);
                    }
                    errhnd::exit(if rejected { RARX_USERBREAK } else { RARX_CREATE });
                }
                it.vol = Some(Vol::File(f));
            }
            next_volume_name(&mut first_vol, false);
        }

        let valid: Vec<bool> = self.items[..tc].iter().map(|it| it.vol.is_some() && !it.new).collect();
        let lost: Vec<usize> = (0..dc).filter(|&i| !valid[i]).collect();
        let Some(mut rs) = gf::Rs16::new(dc, self.rec_count as usize, &valid) else {
            ui_msg(UiMsg::MsgString(MOpFailed.trim_start().to_string()));
            return false;
        };
        // Missing data volumes are replaced by recovery volumes in order.
        let mut substitutes = (dc..tc).filter(|&i| valid[i]);
        let columns: Vec<usize> = (0..dc).map(|i| if valid[i] { i } else { substitutes.next().unwrap() }).collect();
        let block = (BUFFER_SIZE / lost.len()) & !1;
        let mut out = vec![0u8; block * lost.len()];
        let mut input = vec![0u8; block];
        let quiet = cmd.borrow().disable_percentage;
        let (mut done, mut last_percent) = (0i64, -1);
        mprintf("     ");
        loop {
            crate::errhnd::wait();
            let mut longest = 0;
            for (col, &src) in columns.iter().enumerate() {
                let it = &mut self.items[src];
                let n = match it.vol.as_mut() {
                    Some(v) if !it.new => v.read(&mut input),
                    _ => 0,
                };
                input[n..].fill(0);
                longest = longest.max(n);
                let len = (block as u64).min(max_size.wrapping_sub(done as u64)) as usize;
                for (k, o) in out.chunks_mut(block).enumerate() {
                    rs.accumulate(col, k, &input[..len], &mut o[..len], true);
                }
            }
            if longest == 0 {
                break;
            }
            for (k, &i) in lost.iter().enumerate() {
                let it = &mut self.items[i];
                let n = (longest as u64).min(it.size) as usize;
                let data = out[k * block..k * block + n].to_vec();
                it.vol.as_mut().unwrap().write(&data);
                it.size -= n as u64;
            }
            let percent = to_percent(done, rev_size);
            if !quiet && percent != last_percent {
                show_percent(done, rev_size);
                last_percent = percent;
            }
            done += longest as i64;
        }
        for it in &mut self.items {
            if let Some(mut v) = it.vol.take() {
                v.file().keep();
                v.file().close();
            }
        }
        if !quiet {
            mprintf("\x08\x08\x08\x08100%");
        }
        if !silent && !cmd.borrow().disable_done {
            mprintf(MDone);
        }
        true
    }

    fn test(&mut self, cmd: &CmdRef, name: &str) {
        let quiet = cmd.borrow().disable_percentage;
        let mut found = 0;
        test_rev_files(name, |f| {
            let n = self.read_header(f, found == 0);
            if n == 0 {
                return false;
            }
            found += 1;
            file_crc(f, None, true, !quiet) == self.items[n as usize].crc
        });
    }
}
