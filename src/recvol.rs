// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Recovery volumes: RAR 3.x (.rev with 8-bit Reed-Solomon) and
//! RAR 5.0 (.rev with 16-bit Reed-Solomon).

use crate::archive::Archive;
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
const TOTAL_BUFFER_SIZE: usize = 0x4000000;

/// Something we can read volume data from.
enum Src {
    F(File),
    A(Box<Archive>),
}

impl Src {
    fn read(&mut self, b: &mut [u8]) -> i32 {
        match self {
            Src::F(f) => f.read(b),
            Src::A(a) => a.read(b),
        }
    }
    fn write(&mut self, b: &[u8]) {
        match self {
            Src::F(f) => {
                f.write(b);
            }
            Src::A(a) => {
                a.file.write(b);
            }
        }
    }
    fn file(&mut self) -> &mut File {
        match self {
            Src::F(f) => f,
            Src::A(a) => &mut a.file,
        }
    }
}

/// CRC32 of file data. If `from_cur` is false, starts from file beginning.
fn calc_file_crc(f: &mut File, size: Option<i64>, from_cur: bool, show_progress: bool) -> u32 {
    let save = f.tell();
    let file_length = match size {
        Some(s) => s,
        None => f.file_length(),
    };
    if !from_cur {
        f.seek(0, SEEK_SET);
    }
    let mut buf = vec![0u8; 0x100000];
    let mut h = DataHash::new(HashType::Crc32);
    let mut left = size;
    let mut total = 0i64;
    let mut blocks = 0u64;
    loop {
        let n = match left {
            Some(l) => (l.max(0) as usize).min(buf.len()),
            None => buf.len(),
        };
        let r = f.read(&mut buf[..n]);
        if r <= 0 {
            break;
        }
        total += r as i64;
        blocks += 1;
        if blocks & 0xf == 0 && show_progress {
            ui_extract_progress(total, file_length, 0, 0);
        }
        h.update(&buf[..r as usize]);
        if let Some(l) = left.as_mut() {
            *l -= r as i64;
        }
    }
    f.seek(save, SEEK_SET);
    h.crc32()
}

fn ui_process_progress(cur: i64, total: i64) {
    mprintf(&wfmt!("\x08\x08\x08\x08%3d%%", to_percent(cur, total)));
}

pub fn rec_volumes_restore(cmd: &CmdRef, name: &str, silent: bool) -> bool {
    let mut arc = Archive::new(cmd.clone());
    if !arc.open(name, 0) {
        if !silent {
            errhnd::open_error_msg("", name);
        }
        return false;
    }
    let mut rev5 = false;
    if arc.is_archive(true) {
        rev5 = arc.format == crate::archive::RarFormat::Rar50;
    } else {
        let mut sign = [0u8; 8];
        arc.seek(0, SEEK_SET);
        if arc.read(&mut sign) == 8 && &sign == REV5_SIGN {
            rev5 = true;
        }
    }
    arc.close();
    if rev5 {
        RecVolumes5::new().restore(cmd, name, silent)
    } else {
        restore3(cmd, name, silent)
    }
}

pub fn rec_volumes_test(cmd: &CmdRef, arc: Option<&mut Archive>, name: &str) {
    
    let rev_name = match arc {
        None => name.to_string(),
        Some(a) => {
            let (first, num_start) = vol_name_to_first_name(name, a.new_numbering);
            let fc = chars(&first);
            let mut mask: String = fc[..num_start.min(fc.len())].iter().collect();
            mask.push_str("*.rev");
            let mut find = FindFile::new();
            find.set_mask(&mask);
            let mut fd = FindData::default();
            let mut found = String::new();
            while find.next(&mut fd, false) {
                let n = chars(&fd.name);
                let mut num_pos = get_vol_num_pos(&n);
                if at(&n, num_pos) != '1' {
                    continue;
                }
                let mut first_vol = true;
                while num_pos > 0 {
                    num_pos -= 1;
                    if !n[num_pos].is_ascii_digit() {
                        break;
                    }
                    if n[num_pos] != '0' {
                        first_vol = false;
                        break;
                    }
                }
                if first_vol {
                    found = fd.name.clone();
                    break;
                }
            }
            if found.is_empty() {
                return;
            }
            found
        }
    };
    let mut rev = File::new();
    if !rev.open(&rev_name, 0) {
        errhnd::open_error_msg("", &rev_name);
        return;
    }
    mprintf("\n");
    let mut sign = [0u8; 8];
    let is5 = rev.read(&mut sign) == 8 && &sign == REV5_SIGN;
    rev.close();
    if is5 {
        RecVolumes5::new().test(cmd, &rev_name);
    } else {
        test3(cmd, &rev_name);
    }
}

// RAR 3.x recovery volumes.

struct RsCoder {
    gf_exp: [i32; 512],
    gf_log: [i32; 256],
    gx_pol: [i32; 1024],
    error_locs: [i32; 256],
    err_count: i32,
    dnm: [i32; 256],
    par_size: i32,
    el_pol: [i32; 512],
    first_block_done: bool,
}

const MAXPAR: i32 = 255;
const MAXPOL: usize = 512;

impl RsCoder {
    fn new(par_size: i32) -> Self {
        let mut r = RsCoder {
            gf_exp: [0; 512],
            gf_log: [0; 256],
            gx_pol: [0; 1024],
            error_locs: [0; 256],
            err_count: 0,
            dnm: [0; 256],
            par_size,
            el_pol: [0; 512],
            first_block_done: false,
        };
        let mut j = 1;
        for i in 0..MAXPAR {
            r.gf_log[j as usize] = i;
            r.gf_exp[i as usize] = j;
            j <<= 1;
            if j > MAXPAR {
                j ^= 0x11D;
            }
        }
        for i in MAXPAR as usize..MAXPOL {
            r.gf_exp[i] = r.gf_exp[i - MAXPAR as usize];
        }
        let ps = par_size as usize;
        let mut p2 = [0i32; 256];
        p2[0] = 1;
        for i in 1..=ps {
            let mut p1 = [0i32; 256];
            p1[0] = r.gf_exp[i];
            p1[1] = 1;
            let mut res = [0i32; 1024];
            r.pn_mult(&p1, &p2, &mut res);
            r.gx_pol[..ps].copy_from_slice(&res[..ps]);
            p2[..ps].copy_from_slice(&res[..ps]);
        }
        r
    }

    fn gf_mult(&self, a: i32, b: i32) -> i32 {
        if a == 0 || b == 0 {
            0
        } else {
            self.gf_exp[(self.gf_log[a as usize & 255] + self.gf_log[b as usize & 255]) as usize]
        }
    }

    fn pn_mult(&self, p1: &[i32], p2: &[i32], r: &mut [i32]) {
        let ps = self.par_size as usize;
        for x in r[..ps].iter_mut() {
            *x = 0;
        }
        for i in 0..ps {
            if p1[i] != 0 {
                for j in 0..ps - i {
                    r[i + j] ^= self.gf_mult(p1[i], p2[j]);
                }
            }
        }
    }

    fn decode(&mut self, data: &mut [u8], era_loc: &[i32]) -> bool {
        let ps = self.par_size as usize;
        let data_size = data.len() as i32;
        let mut syn = [0i32; MAXPOL];
        let mut all_zero = true;
        for i in 0..ps {
            let mut sum = 0;
            for &d in data.iter() {
                sum = d as i32 ^ self.gf_mult(self.gf_exp[i + 1], sum);
            }
            syn[i] = sum;
            if sum != 0 {
                all_zero = false;
            }
        }
        if all_zero {
            return true;
        }
        if !self.first_block_done {
            self.first_block_done = true;
            for x in self.el_pol[..ps + 1].iter_mut() {
                *x = 0;
            }
            self.el_pol[0] = 1;
            for &e in era_loc {
                let m = self.gf_exp[(data_size - e - 1).rem_euclid(512) as usize];
                for i in (1..=ps).rev() {
                    self.el_pol[i] ^= self.gf_mult(m, self.el_pol[i - 1]);
                }
            }
            self.err_count = 0;
            for root in (MAXPAR - data_size)..(MAXPAR + 1) {
                let mut sum = 0;
                for b in 0..ps + 1 {
                    sum ^= self.gf_mult(self.gf_exp[((b as i32 * root) % MAXPAR) as usize], self.el_pol[b]);
                }
                if sum == 0 {
                    let ec = self.err_count as usize;
                    if ec >= 256 {
                        break;
                    }
                    self.error_locs[ec] = MAXPAR - root;
                    self.dnm[ec] = 0;
                    let mut i = 1;
                    while i < ps + 1 {
                        self.dnm[ec] ^= self.gf_mult(self.el_pol[i], self.gf_exp[(root * (i as i32 - 1) % MAXPAR) as usize]);
                        i += 2;
                    }
                    self.err_count += 1;
                }
            }
        }
        let mut ee = [0i32; MAXPOL];
        let el = self.el_pol;
        self.pn_mult(&el, &syn, &mut ee);
        if self.err_count <= self.par_size && self.err_count > 0 {
            for i in 0..self.err_count as usize {
                let loc = self.error_locs[i];
                let dloc = MAXPAR - loc;
                let mut n = 0;
                for j in 0..ps {
                    n ^= self.gf_mult(ee[j], self.gf_exp[(dloc * j as i32 % MAXPAR) as usize]);
                }
                let pos = data_size - loc - 1;
                if pos >= 0 && pos < data_size {
                    let inv = self.gf_exp[(MAXPAR - self.gf_log[self.dnm[i] as usize & 255]) as usize];
                    data[pos as usize] ^= self.gf_mult(n, inv) as u8;
                }
            }
        }
        self.err_count <= self.par_size
    }
}

fn is_new_style_rev(name: &str) -> bool {
    let p = match get_ext_pos(name) {
        None | Some(0) => return true,
        Some(p) => p,
    };
    let v = chars(name);
    let mut ext_pos = name[..p].chars().count();
    let mut digit_group = 0;
    ext_pos -= 1;
    while ext_pos > 0 {
        if !v[ext_pos].is_ascii_digit() {
            if v[ext_pos] == '_' && v[ext_pos - 1].is_ascii_digit() {
                digit_group += 1;
            } else {
                break;
            }
        }
        ext_pos -= 1;
    }
    digit_group < 2
}

fn restore3(cmd: &CmdRef, name: &str, silent: bool) -> bool {
    let mut arc_name = name.to_string();
    let mut new_style = false;
    let rev_name = cmp_ext(&arc_name, "rev");
    if rev_name {
        new_style = is_new_style_rev(&arc_name);
        let v = chars(&arc_name);
        let mut ep = arc_name[..get_ext_pos(&arc_name).unwrap()].chars().count();
        while ep > 1 && (v[ep - 1].is_ascii_digit() || v[ep - 1] == '_') {
            ep -= 1;
        }
        arc_name = v[..ep].iter().collect::<String>() + "*.*";
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
    if !arc.w_check_open(&arc_name) {
        return false;
    }
    if !arc.volume {
        return false;
    }
    let new_numbering = arc.new_numbering;
    arc.close();
    let (first, vol_num_start) = vol_name_to_first_name(&arc_name, new_numbering);
    arc_name = first;
    let av = chars(&arc_name);
    let rec_vol_mask = av[..vol_num_start.min(av.len())].iter().collect::<String>() + "*.rev";
    let base_len = vol_num_start;
    if base_len == 0 {
        return false;
    }
    let mut src: Vec<Option<Src>> = (0..256).map(|_| None).collect();
    let mut rec_file_size: i64 = 0;
    let mut calc_msg_done = false;
    let mut find = FindFile::new();
    find.set_mask(&rec_vol_mask);
    let mut rd = FindData::default();
    let (mut file_number, mut rec_vol_number, mut found_rec, mut missing) = (0i32, 0i32, 0u32, 0u32);
    let mut prev_name = String::new();
    while find.next(&mut rd, false) {
        let cur_name = rd.name.clone();
        let mut p = [0i32; 3];
        if !rev_name && !new_style {
            new_style = true;
            if let Some(dp) = get_ext_pos(&cur_name) {
                let v = chars(&cur_name);
                let mut d = cur_name[..dp].chars().count();
                let mut lines = 0;
                d -= 1;
                while d > 0 && v[d] != '.' {
                    if v[d] == '_' {
                        lines += 1;
                    }
                    d -= 1;
                }
                if lines == 2 {
                    new_style = false;
                }
            }
        }
        if new_style {
            if !calc_msg_done {
                ui_msg(UiMsg::RecVolCalcChecksum);
                calc_msg_done = true;
            }
            ui_msg(UiMsg::MsgString(cur_name.clone()));
            let mut f = File::new();
            f.t_open(&cur_name);
            f.seek(0, SEEK_END);
            let length = f.tell();
            if length < 7 {
                continue;
            }
            f.seek(length - 7, SEEK_SET);
            for i in 0..3 {
                p[2 - i] = f.get_byte() as i32 + 1;
            }
            let mut file_crc = 0u32;
            for i in 0..4 {
                file_crc |= (f.get_byte() as u32) << (i * 8);
            }
            let calc = calc_file_crc(&mut f, Some(length - 4), false, false);
            if file_crc != calc {
                ui_msg(UiMsg::MsgChecksum(cur_name.clone()));
                continue;
            }
        } else {
            let dp = match get_ext_pos(&cur_name) {
                None => continue,
                Some(d) => d,
            };
            let v = chars(&cur_name);
            let mut d = cur_name[..dp].chars().count();
            let mut wrong = false;
            for x in p.iter_mut() {
                loop {
                    if d == 0 {
                        break;
                    }
                    d -= 1;
                    if !(v[d].is_ascii_digit() && d >= base_len) {
                        break;
                    }
                }
                *x = atoiw(&v[d + 1..].iter().collect::<String>()) as i32;
                if *x == 0 || *x > 255 {
                    wrong = true;
                }
            }
            if wrong {
                continue;
            }
        }
        if p[0] <= 0 || p[1] <= 0 || p[2] <= 0 || p[1] + p[2] > 255 || p[0] + p[2] - 1 > 255 {
            continue;
        }
        if rec_vol_number != 0 && rec_vol_number != p[1] || file_number != 0 && file_number != p[2] {
            ui_msg(UiMsg::RecVolDiffSets(cur_name, prev_name));
            return false;
        }
        rec_vol_number = p[1];
        file_number = p[2];
        prev_name = cur_name.clone();
        let mut nf = File::new();
        nf.t_open(&cur_name);
        let pos = (file_number + p[0] - 1) as usize;
        if pos >= 256 || src[pos].is_some() {
            continue;
        }
        if rec_file_size == 0 {
            rec_file_size = nf.file_length();
        }
        src[pos] = Some(Src::F(nf));
        found_rec += 1;
    }
    if !silent || found_rec != 0 {
        ui_msg(UiMsg::RecVolFound(found_rec));
    }
    if found_rec == 0 {
        return false;
    }
    let mut write_flags = [false; 256];
    let mut last_vol_name = String::new();
    for cur in 0..file_number as usize {
        let mut nf = Box::new(Archive::new(cmd.clone()));
        let mut valid = file_exist(&arc_name);
        if valid {
            nf.file.t_open(&arc_name);
            valid = nf.is_archive(false);
            if valid {
                while nf.read_header() != 0 {
                    if nf.get_header_type() == HEAD_ENDARC {
                        ui_msg(UiMsg::MsgString(arc_name.clone()));
                        if nf.end_arc_head.data_crc {
                            let cbp = nf.cur_block_pos;
                            let c = calc_file_crc(&mut nf.file, Some(cbp), false, false);
                            if nf.end_arc_head.arc_data_crc != c {
                                valid = false;
                                ui_msg(UiMsg::MsgChecksum(arc_name.clone()));
                            }
                        }
                        break;
                    }
                    nf.seek_to_next();
                }
            }
            if !valid {
                nf.close();
                let new_name = format!("{}.bad", arc_name);
                ui_msg(UiMsg::MsgBadArchive(arc_name.clone()));
                ui_msg(UiMsg::MsgRenaming(arc_name.clone(), new_name.clone()));
                rename_file(&arc_name, &new_name);
            }
            nf.seek(0, SEEK_SET);
        }
        if !valid {
            if !nf.file.create(&arc_name, crate::file::FMF_WRITE | crate::file::FMF_SHAREREAD) {
                ui_msg(UiMsg::Reconstructing);
                errhnd::create_error_msg("", &arc_name);
                return false;
            }
            write_flags[cur] = true;
            missing += 1;
            if cur as i32 == file_number - 1 {
                last_vol_name = arc_name.clone();
            }
            ui_msg(UiMsg::MsgMissingVol(arc_name.clone()));
        }
        src[cur] = Some(Src::A(nf));
        next_volume_name(&mut arc_name, !new_numbering);
    }
    ui_msg(UiMsg::RecVolMissing(missing));
    if missing == 0 {
        ui_msg(UiMsg::RecVolAllExist);
        return false;
    }
    if missing > found_rec {
        ui_msg(UiMsg::RecVolCannotFix);
        return false;
    }
    ui_msg(UiMsg::MsgReconstructing);
    let total = (file_number + rec_vol_number) as usize;
    let erasures: Vec<i32> = (0..total).filter(|&i| write_flags[i] || src[i].is_none()).map(|i| i as i32).collect();
    let mut processed: i64 = 0;
    let mut last_percent = -1;
    mprintf("     ");
    let rbs = TOTAL_BUFFER_SIZE / total;
    let mut buf = vec![0u8; TOTAL_BUFFER_SIZE];
    let mut rs = RsCoder::new(rec_vol_number);
    let disable_percentage = cmd.borrow().disable_percentage;
    loop {
        crate::errhnd::wait();
        let mut max_read = 0usize;
        for i in 0..total {
            let area = &mut buf[i * rbs..(i + 1) * rbs];
            if write_flags[i] || src[i].is_none() {
                area.fill(0);
            } else {
                let r = src[i].as_mut().unwrap().read(area).max(0) as usize;
                area[r..].fill(0);
                max_read = max_read.max(r);
            }
        }
        if max_read == 0 {
            break;
        }
        let cur = to_percent(processed, rec_file_size);
        if !disable_percentage && cur != last_percent {
            ui_process_progress(processed, rec_file_size);
            last_percent = cur;
        }
        processed += max_read as i64;
        let mut data = vec![0u8; total];
        for pos in 0..max_read {
            for i in 0..total {
                data[i] = buf[i * rbs + pos];
            }
            rs.decode(&mut data, &erasures);
            for &e in &erasures {
                buf[e as usize * rbs + pos] = data[e as usize];
            }
        }
        for i in 0..file_number as usize {
            if write_flags[i] {
                let s = buf[i * rbs..i * rbs + max_read].to_vec();
                src[i].as_mut().unwrap().write(&s);
            }
        }
    }
    for i in 0..total {
        if let Some(mut s) = src[i].take() {
            if new_style && write_flags[i] {
                let f = s.file();
                let len = f.tell();
                f.seek(len - 7, SEEK_SET);
                f.write(&[0u8; 7]);
            }
            let f = s.file();
            f.keep();
            f.close();
        }
    }
    if !last_vol_name.is_empty() {
        let mut a = Archive::new(cmd.clone());
        if a.open(&last_vol_name, crate::file::FMF_UPDATE) && a.is_archive(true) && a.search_block(HEAD_ENDARC) != 0 {
            let p = a.next_block_pos;
            a.seek(p, SEEK_SET);
            let mut b = vec![0u8; 8192];
            let r = a.read(&mut b).max(0) as usize;
            if b[..r].iter().all(|&x| x == 0) {
                a.seek(p, SEEK_SET);
                a.file.truncate();
            }
        }
    }
    if !disable_percentage {
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
    let mut vol_name = name.to_string();
    while file_exist(&vol_name) {
        let mut f = File::new();
        if !f.open(&vol_name, 0) {
            errhnd::open_error_msg("", &vol_name);
            next_volume_name(&mut vol_name, false);
            continue;
        }
        mprintf(&wfmt!(MExtrTestFile, vol_name.as_str()));
        mprintf("     ");
        f.seek(0, SEEK_END);
        let length = f.tell();
        f.seek(length - 4, SEEK_SET);
        let mut file_crc = 0u32;
        for i in 0..4 {
            file_crc |= (f.get_byte() as u32) << (i * 8);
        }
        let dp = cmd.borrow().disable_percentage;
        let calc = calc_file_crc(&mut f, Some(length - 4), false, !dp);
        if file_crc == calc {
            mprintf(&wfmt!("%s%s ", "\x08\x08\x08\x08\x08 ", MOk));
        } else {
            ui_msg(UiMsg::Checksum(vol_name.clone(), vol_name.clone()));
            set_error_code(RARX_CRC);
        }
        next_volume_name(&mut vol_name, false);
    }
}

// RAR 5.0 recovery volumes.

struct RsCoder16 {
    gf_exp: Vec<u32>,
    gf_log: Vec<u32>,
    nd: u32,
    nr: u32,
    ne: u32,
    valid_flags: Vec<bool>,
    mx: Vec<u32>,
    data_log: Vec<u32>,
}

const GF_SIZE: u32 = 65535;

impl RsCoder16 {
    fn new() -> Self {
        let mut gf_exp = vec![0u32; 4 * GF_SIZE as usize + 1];
        let mut gf_log = vec![0u32; GF_SIZE as usize + 1];
        let mut e: u32 = 1;
        for l in 0..GF_SIZE {
            gf_log[e as usize] = l;
            gf_exp[l as usize] = e;
            gf_exp[(l + GF_SIZE) as usize] = e;
            e <<= 1;
            if e > GF_SIZE {
                e ^= 0x1100B;
            }
        }
        gf_log[0] = 2 * GF_SIZE;
        for i in 2 * GF_SIZE..=4 * GF_SIZE {
            gf_exp[i as usize] = 0;
        }
        RsCoder16 { gf_exp, gf_log, nd: 0, nr: 0, ne: 0, valid_flags: Vec::new(), mx: Vec::new(), data_log: Vec::new() }
    }

    fn gf_mul(&self, a: u32, b: u32) -> u32 {
        self.gf_exp[(self.gf_log[a as usize] + self.gf_log[b as usize]) as usize]
    }

    fn gf_inv(&self, a: u32) -> u32 {
        if a == 0 {
            0
        } else {
            self.gf_exp[(GF_SIZE - self.gf_log[a as usize]) as usize]
        }
    }

    fn init(&mut self, nd: u32, nr: u32, valid: &[bool]) -> bool {
        self.nd = nd;
        self.nr = nr;
        self.ne = 0;
        self.valid_flags = valid[..(nd + nr) as usize].to_vec();
        for i in 0..nd as usize {
            if !self.valid_flags[i] {
                self.ne += 1;
            }
        }
        let valid_ecc = self.valid_flags[nd as usize..].iter().filter(|&&v| v).count() as u32;
        if self.ne > valid_ecc || self.ne == 0 || valid_ecc == 0 {
            return false;
        }
        if nd + nr > GF_SIZE || nd == 0 || nr == 0 {
            return false;
        }
        self.mx = vec![0; (self.ne * nd) as usize];
        // Decoder matrix.
        let (mut r, mut dest) = (nd as usize, 0usize);
        for flag in 0..nd as usize {
            if !self.valid_flags[flag] {
                while !self.valid_flags[r] {
                    r += 1;
                }
                for j in 0..nd as usize {
                    self.mx[dest * nd as usize + j] = self.gf_inv((r ^ j) as u32);
                }
                dest += 1;
                r += 1;
            }
        }
        self.invert_decoder_matrix();
        true
    }

    fn invert_decoder_matrix(&mut self) {
        let nd = self.nd as usize;
        let ne = self.ne as usize;
        let mut mi = vec![0u32; ne * nd];
        let mut kf = 0;
        for kr in 0..ne {
            while self.valid_flags[kf] {
                kf += 1;
            }
            mi[kr * nd + kf] = 1;
            kf += 1;
        }
        let (mut kr, mut kf) = (0usize, 0usize);
        while kf < nd {
            while kf < nd && self.valid_flags[kf] {
                for i in 0..ne {
                    mi[i * nd + kf] ^= self.mx[i * nd + kf];
                }
                kf += 1;
            }
            if kf == nd {
                break;
            }
            let pinv = self.gf_inv(self.mx[kr * nd + kf]);
            for i in 0..nd {
                self.mx[kr * nd + i] = self.gf_mul(self.mx[kr * nd + i], pinv);
                mi[kr * nd + i] = self.gf_mul(mi[kr * nd + i], pinv);
            }
            for i in 0..ne {
                if i != kr {
                    let mik = self.mx[i * nd + kf];
                    for j in 0..nd {
                        let a = self.gf_mul(self.mx[kr * nd + j], mik);
                        let b = self.gf_mul(mi[kr * nd + j], mik);
                        self.mx[i * nd + j] ^= a;
                        mi[i * nd + j] ^= b;
                    }
                }
            }
            kr += 1;
            kf += 1;
        }
        self.mx = mi;
    }

    fn update_ecc(&mut self, data_num: u32, ecc_num: u32, data: &[u8], ecc: &mut [u8]) {
        let bs = ecc.len();
        if data_num == 0 {
            ecc.fill(0);
        }
        if ecc_num == 0 {
            self.data_log.resize(bs, 0);
            let mut i = 0;
            while i < bs {
                let d = data[i] as usize + data.get(i + 1).copied().unwrap_or(0) as usize * 256;
                self.data_log[i] = self.gf_log[d];
                i += 2;
            }
        }
        let ml = self.gf_log[self.mx[(ecc_num * self.nd + data_num) as usize] as usize];
        let mut i = 0;
        while i < bs {
            let r = self.gf_exp[(ml + self.data_log[i]) as usize];
            ecc[i] ^= r as u8;
            if i + 1 < bs {
                ecc[i + 1] ^= (r >> 8) as u8;
            }
            i += 2;
        }
    }
}

#[derive(Default)]
struct RecVolItem {
    f: Option<Src>,
    name: String,
    crc: u32,
    file_size: u64,
    new: bool,
    valid: bool,
}

struct RecVolumes5 {
    items: Vec<RecVolItem>,
    data_count: u32,
    rec_count: u32,
    total_count: u32,
}

impl RecVolumes5 {
    fn new() -> Self {
        RecVolumes5 { items: Vec::new(), data_count: 0, rec_count: 0, total_count: 0 }
    }

    fn read_header(&mut self, f: &mut File, first_rev: bool) -> u32 {
        let mut sb = [0u8; 16];
        if f.read(&mut sb) != 16 || &sb[..8] != REV5_SIGN {
            return 0;
        }
        let header_size = u32::from_le_bytes(sb[12..16].try_into().unwrap());
        if header_size > 0x100000 || header_size <= 5 {
            return 0;
        }
        let block_crc = u32::from_le_bytes(sb[8..12].try_into().unwrap());
        let mut raw = crate::rawread::RawRead::new();
        if raw.read_from(header_size as usize, None, &mut |b| f.read(b)) != header_size as usize {
            return 0;
        }
        let c = crate::hash::crc32::crc32(0xffffffff, &sb[12..16]);
        if crate::hash::crc32::crc32(c, raw.data()) ^ 0xffffffff != block_crc {
            return 0;
        }
        if raw.get1() != 1 {
            return 0;
        }
        let dc = raw.get2() as u32;
        let rc = raw.get2() as u32;
        if !first_rev && (dc != self.data_count || rc != self.rec_count) {
            return 0;
        }
        self.data_count = dc;
        self.rec_count = rc;
        self.total_count = dc + rc;
        let rec_num = raw.get2() as u32;
        if rec_num >= self.total_count || self.total_count > 65535 {
            return 0;
        }
        let rev_crc = raw.get4();
        if first_rev {
            self.items.resize_with(self.total_count as usize, Default::default);
            for i in 0..dc as usize {
                self.items[i].file_size = raw.get8();
                self.items[i].crc = raw.get4();
            }
        }
        if (rec_num as usize) < self.items.len() {
            self.items[rec_num as usize].crc = rev_crc;
        }
        rec_num
    }

    fn restore(&mut self, cmd: &CmdRef, name: &str, silent: bool) -> bool {
        let v = chars(name);
        let mut num_pos = get_vol_num_pos(&v);
        while num_pos > 0 && v[num_pos - 1].is_ascii_digit() {
            num_pos -= 1;
        }
        if num_pos <= get_name_pos_c(&v) {
            return false;
        }
        let arc_mask = v[..num_pos].iter().collect::<String>() + "*.*";
        let mut first_vol_name = String::new();
        let mut longest_rev = String::new();
        let mut rec_file_size: i64 = 0;
        let mut first_vol_size: u64 = 0;
        let mut find = FindFile::new();
        find.set_mask(&arc_mask);
        let mut fd = FindData::default();
        let mut found_rec: u32 = 0;
        while find.next(&mut fd, false) {
            crate::errhnd::wait();
            let mut vol = Box::new(Archive::new(cmd.clone()));
            let mut item_pos: i64 = -1;
            if !fd.is_dir && vol.w_open(&fd.name) {
                if cmp_ext(&fd.name, "rev") {
                    let rn = self.read_header(&mut vol.file, found_rec == 0);
                    if rn != 0 {
                        if found_rec == 0 {
                            rec_file_size = vol.file.file_length();
                        }
                        item_pos = rn as i64;
                        found_rec += 1;
                        if fd.name.len() > longest_rev.len() {
                            longest_rev = fd.name.clone();
                        }
                    }
                } else if vol.is_archive(true) && (vol.sfx_size > 0 || cmp_ext(&fd.name, "rar")) {
                    if !vol.volume && !vol.broken_header {
                        return false;
                    }
                    let n = vol.file_name().to_string();
                    vol.open(&n, 0);
                    vol.seek(0, SEEK_SET);
                    let nv = chars(&fd.name);
                    let mut np = get_vol_num_pos(&nv) as i64;
                    let mut vol_num: u64 = 0;
                    let mut k = 1u64;
                    while np >= 0 && nv[np as usize].is_ascii_digit() {
                        vol_num += (nv[np as usize] as u64 - '0' as u64) * k;
                        k *= 10;
                        np -= 1;
                    }
                    if vol_num == 0 || vol_num > 65535 {
                        continue;
                    }
                    if first_vol_size == 0 {
                        first_vol_size = vol.file.file_length() as u64;
                    }
                    if vol_num as usize > self.items.len() {
                        self.items.resize_with(vol_num as usize, Default::default);
                    }
                    item_pos = vol_num as i64 - 1;
                    if first_vol_name.is_empty() {
                        first_vol_name = vol_name_to_first_name(&fd.name, true).0;
                    }
                }
            }
            if item_pos >= 0 && (item_pos as usize) < self.items.len() {
                let it = &mut self.items[item_pos as usize];
                it.f = Some(Src::A(vol));
                it.new = false;
                it.name = fd.name.clone();
            }
        }
        if !silent || found_rec != 0 {
            ui_msg(UiMsg::RecVolFound(found_rec));
        }
        if found_rec == 0 {
            return false;
        }
        if first_vol_name.is_empty() {
            set_ext(&mut longest_rev, "rar");
            first_vol_name = vol_name_to_first_name(&longest_rev, true).0;
        }
        ui_msg(UiMsg::RecVolCalcChecksum);
        let dc = self.data_count as usize;
        let tc = self.total_count as usize;
        if self.items.len() < tc {
            self.items.resize_with(tc, Default::default);
        }
        let mut missing = 0u32;
        for i in 0..tc {
            let it = &mut self.items[i];
            if let Some(f) = it.f.as_mut() {
                ui_msg(UiMsg::MsgString(it.name.clone()));
                let crc = calc_file_crc(f.file(), None, true, false);
                it.valid = crc == it.crc;
                if !it.valid {
                    ui_msg(UiMsg::MsgChecksum(it.name.clone()));
                    if i >= dc {
                        it.f = None;
                        found_rec -= 1;
                    }
                }
            }
            if i < dc && (it.f.is_none() || !it.valid) {
                missing += 1;
            }
        }
        ui_msg(UiMsg::RecVolMissing(missing));
        if missing == 0 {
            ui_msg(UiMsg::RecVolAllExist);
            return false;
        }
        if missing > found_rec {
            ui_msg(UiMsg::RecVolCannotFix);
            return false;
        }
        ui_msg(UiMsg::MsgReconstructing);
        let mut max_vol_size = 0u64;
        for i in 0..dc {
            let it = &mut self.items[i];
            max_vol_size = max_vol_size.max(it.file_size);
            if it.f.is_some() && !it.valid {
                it.f = None;
                let nn = format!("{}.bad", it.name);
                ui_msg(UiMsg::MsgBadArchive(it.name.clone()));
                ui_msg(UiMsg::MsgRenaming(it.name.clone(), nn.clone()));
                rename_file(&it.name, &nn);
            }
            it.new = it.f.is_none();
            if it.new {
                it.name = first_vol_name.clone();
                ui_msg(UiMsg::Creating(it.name.clone()));
                let mut nf = File::new();
                let (ok, reject) = {
                    let mut c = cmd.borrow_mut();
                    file_create(&mut c, Some(&mut nf), &mut it.name, None, None, 0)
                };
                if !ok {
                    if !reject {
                        errhnd::create_error_msg("", &it.name);
                    }
                    errhnd::exit(if reject { RARX_USERBREAK } else { RARX_CREATE });
                }
                it.f = Some(Src::F(nf));
            }
            next_volume_name(&mut first_vol_name, false);
        }
        let mut processed: i64 = 0;
        let mut last_percent = -1;
        mprintf("     ");
        let mut valid = vec![false; tc];
        missing = 0;
        for i in 0..tc {
            valid[i] = self.items[i].f.is_some() && !self.items[i].new;
            if i < dc && !valid[i] {
                missing += 1;
            }
        }
        let mut rbs = TOTAL_BUFFER_SIZE / missing as usize;
        rbs &= !1;
        let mut rs = RsCoder16::new();
        if !rs.init(self.data_count, self.rec_count, &valid) {
            ui_msg(UiMsg::MsgString(crate::loclang::MOpFailed.trim_start().to_string()));
            return false;
        }
        let mut buf = vec![0u8; rbs * missing as usize];
        let mut read_buf = vec![0u8; rbs];
        let dp = cmd.borrow().disable_percentage;
        loop {
            crate::errhnd::wait();
            let mut max_read = 0usize;
            let mut j = dc;
            for i in 0..dc {
                let mut vol_num = i;
                if !valid[i] {
                    while !valid[j] {
                        j += 1;
                    }
                    vol_num = j;
                    j += 1;
                }
                let it = &mut self.items[vol_num];
                let mut r = 0usize;
                if !it.new {
                    if let Some(f) = it.f.as_mut() {
                        r = f.read(&mut read_buf).max(0) as usize;
                    }
                }
                read_buf[r..].fill(0);
                max_read = max_read.max(r);
                let to_process = (rbs as u64).min(max_vol_size.wrapping_sub(processed as u64)) as usize;
                for e in 0..missing {
                    let off = e as usize * rbs;
                    rs.update_ecc(i as u32, e, &read_buf[..to_process], &mut buf[off..off + to_process]);
                }
            }
            if max_read == 0 {
                break;
            }
            let mut j = 0;
            for i in 0..dc {
                if !valid[i] {
                    let it = &mut self.items[i];
                    let ws = (max_read as u64).min(it.file_size) as usize;
                    let s = buf[j * rbs..j * rbs + ws].to_vec();
                    it.f.as_mut().unwrap().write(&s);
                    it.file_size -= ws as u64;
                    j += 1;
                }
            }
            let cur = to_percent(processed, rec_file_size);
            if !dp && cur != last_percent {
                ui_process_progress(processed, rec_file_size);
                last_percent = cur;
            }
            processed += max_read as i64;
        }
        for it in self.items.iter_mut() {
            if let Some(mut f) = it.f.take() {
                f.file().keep();
                f.file().close();
            }
        }
        if !dp {
            mprintf("\x08\x08\x08\x08100%");
        }
        if !silent && !cmd.borrow().disable_done {
            mprintf(MDone);
        }
        true
    }

    fn test(&mut self, cmd: &CmdRef, name: &str) {
        let mut vol_name = name.to_string();
        let mut found = 0;
        while file_exist(&vol_name) {
            let mut f = File::new();
            if !f.open(&vol_name, 0) {
                errhnd::open_error_msg("", &vol_name);
                next_volume_name(&mut vol_name, false);
                continue;
            }
            mprintf(&wfmt!(MExtrTestFile, vol_name.as_str()));
            mprintf("     ");
            let mut valid = false;
            let rn = self.read_header(&mut f, found == 0);
            if rn != 0 {
                found += 1;
                let dp = cmd.borrow().disable_percentage;
                let crc = calc_file_crc(&mut f, None, true, !dp);
                valid = crc == self.items[rn as usize].crc;
            }
            if valid {
                mprintf(&wfmt!("%s%s ", "\x08\x08\x08\x08\x08 ", MOk));
            } else {
                ui_msg(UiMsg::Checksum(vol_name.clone(), vol_name.clone()));
                set_error_code(RARX_CRC);
            }
            next_volume_name(&mut vol_name, false);
        }
    }
}
