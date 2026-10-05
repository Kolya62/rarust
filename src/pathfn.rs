// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Path and file name helpers.

use crate::strfn::{atoiw, wcsicomp_eq};

#[cfg(unix)]
pub const CPATHDIVIDER: char = '/';
#[cfg(not(unix))]
pub const CPATHDIVIDER: char = '\\';

pub fn is_path_div(c: char) -> bool {
    if cfg!(unix) {
        c == CPATHDIVIDER
    } else {
        c == '\\' || c == '/'
    }
}

pub fn is_drive_div(c: char) -> bool {
    !cfg!(unix) && c == ':'
}

pub(crate) fn chars(s: &str) -> Vec<char> {
    s.chars().collect()
}

pub(crate) fn at(v: &[char], i: usize) -> char {
    v.get(i).copied().unwrap_or('\0')
}

pub fn is_drive_letter(path: &str) -> bool {
    let v: Vec<char> = path.chars().take(2).collect();
    if v.len() < 2 {
        return false;
    }
    let l = v[0].to_ascii_uppercase();
    l.is_ascii_uppercase() && is_drive_div(v[1])
}

/// Character position where the name part starts.
pub fn get_name_pos_c(p: &[char]) -> usize {
    for i in (0..p.len()).rev() {
        if is_path_div(p[i]) {
            return i + 1;
        }
    }
    if p.len() >= 2 && p[0].is_ascii_alphabetic() && is_drive_div(p[1]) {
        2
    } else {
        0
    }
}

/// Byte position where the name part starts.
pub fn get_name_pos(path: &str) -> usize {
    let v = chars(path);
    let cp = get_name_pos_c(&v);
    char_to_byte(path, cp)
}

fn char_to_byte(s: &str, cp: usize) -> usize {
    s.char_indices().nth(cp).map(|(b, _)| b).unwrap_or(s.len())
}

pub fn point_to_name(path: &str) -> &str {
    &path[get_name_pos(path)..]
}

pub fn get_last_char(path: &str) -> char {
    path.chars().last().unwrap_or('\0')
}

/// Remove dangerous path prefixes and "..". Returns the number of removed
/// characters and the converted path.
pub fn convert_path(src: &str) -> (usize, String) {
    let s = chars(src);
    let mut dest_pos = 0usize;
    for i in 0..s.len() {
        if is_path_div(s[i]) && at(&s, i + 1) == '.' && at(&s, i + 2) == '.' && (is_path_div(at(&s, i + 3)) || at(&s, i + 3) == '\0') {
            dest_pos = if at(&s, i + 3) == '\0' { i + 3 } else { i + 4 };
        }
    }
    while dest_pos < s.len() {
        let mut i = dest_pos;
        if i + 1 < s.len() && is_drive_div(s[i + 1]) {
            i += 2;
        }
        if is_path_div(at(&s, i)) && is_path_div(at(&s, i + 1)) {
            let mut slash_count = 0;
            for j in i + 2..s.len() {
                if is_path_div(s[j]) {
                    slash_count += 1;
                    if slash_count == 2 {
                        i = j + 1;
                        break;
                    }
                }
            }
        }
        for j in i..s.len() {
            if is_path_div(s[j]) {
                i = j + 1;
            } else if s[j] != '.' {
                break;
            }
        }
        if i == dest_pos {
            break;
        }
        dest_pos = i;
    }
    let dest_pos = dest_pos.min(s.len());
    (dest_pos, s[dest_pos..].iter().collect())
}

pub fn set_name(full: &mut String, name: &str) {
    let p = get_name_pos(full);
    full.truncate(p);
    full.push_str(name);
}

pub fn get_ext_pos(name: &str) -> Option<usize> {
    let np = get_name_pos(name);
    match name.rfind('.') {
        Some(d) if d >= np => Some(d),
        _ => None,
    }
}

/// Extension with the leading dot or empty string.
pub fn get_ext(name: &str) -> &str {
    match get_ext_pos(name) {
        Some(p) => &name[p..],
        None => "",
    }
}

pub fn set_ext(name: &mut String, new_ext: &str) {
    if let Some(p) = get_ext_pos(name) {
        name.truncate(p);
    }
    name.push('.');
    name.push_str(new_ext);
}

pub fn remove_ext(name: &mut String) {
    if let Some(p) = get_ext_pos(name) {
        name.truncate(p);
    }
}

/// Compare extension without the leading dot, case insensitive.
pub fn cmp_ext(name: &str, ext: &str) -> bool {
    match get_ext_pos(name) {
        None => ext.is_empty(),
        Some(p) => wcsicomp_eq(&name[p + 1..], ext),
    }
}

pub fn is_wildcard(s: &str) -> bool {
    s.contains('*') || s.contains('?')
}

pub fn add_end_slash(path: &mut String) {
    if !path.is_empty() && !path.ends_with(CPATHDIVIDER) {
        path.push(CPATHDIVIDER);
    }
}

pub fn make_name(path: &str, name: &str) -> String {
    let mut out = path.to_string();
    if !is_drive_letter(path) || path.chars().count() > 2 {
        add_end_slash(&mut out);
    }
    out.push_str(name);
    out
}

/// File path including the trailing separator.
pub fn get_path_with_sep(full: &str) -> String {
    full[..get_name_pos(full)].to_string()
}

pub fn remove_name_from_path(path: &mut String) {
    let v = chars(path);
    let mut np = get_name_pos_c(&v);
    if np >= 2 && (!is_drive_div(v[1]) || np >= 4) {
        np -= 1;
    }
    path.truncate(char_to_byte(path, np));
}

pub fn get_vol_num_pos(arc: &[char]) -> usize {
    let name_pos = get_name_pos_c(arc);
    if name_pos == arc.len() {
        return name_pos;
    }
    let mut pos = arc.len() - 1;
    while !arc[pos].is_ascii_digit() && pos > name_pos {
        pos -= 1;
    }
    let mut num_pos = pos;
    while arc[num_pos].is_ascii_digit() && num_pos > name_pos {
        num_pos -= 1;
    }
    while num_pos > name_pos && arc[num_pos] != '.' {
        if arc[num_pos].is_ascii_digit() {
            let dot = arc[name_pos..].iter().position(|&c| c == '.').map(|p| p + name_pos);
            if let Some(d) = dot {
                if d < num_pos {
                    pos = num_pos;
                }
            }
            break;
        }
        num_pos -= 1;
    }
    pos
}

pub fn next_volume_name(arc_name: &mut String, old_numbering: bool) {
    let mut dot_pos = get_ext_pos(arc_name);
    match dot_pos {
        None => {
            arc_name.push_str(".rar");
            dot_pos = get_ext_pos(arc_name);
        }
        Some(p) => {
            if p + 1 == arc_name.len() || cmp_ext(arc_name, "exe") || cmp_ext(arc_name, "sfx") {
                set_ext(arc_name, "rar");
                dot_pos = get_ext_pos(arc_name);
            }
        }
    }
    let mut v = chars(arc_name);
    // Convert byte position to char position.
    let dot = arc_name[..dot_pos.unwrap()].chars().count();
    if !old_numbering {
        let mut num_pos = get_vol_num_pos(&v);
        loop {
            v[num_pos] = char::from_u32(v[num_pos] as u32 + 1).unwrap_or('0');
            if v[num_pos] != ':' {
                break;
            }
            v[num_pos] = '0';
            if num_pos == 0 {
                break;
            }
            num_pos -= 1;
            if !v[num_pos].is_ascii_digit() {
                v.insert(num_pos + 1, '1');
                break;
            }
        }
    } else {
        if v.len() - dot < 3 {
            v.truncate(dot + 1);
            v.extend("rar".chars());
        }
        if !at(&v, dot + 2).is_ascii_digit() || !at(&v, dot + 3).is_ascii_digit() {
            v.truncate(dot + 2);
            v.extend("00".chars());
        } else {
            let mut num_pos = v.len() - 1;
            loop {
                v[num_pos] = char::from_u32(v[num_pos] as u32 + 1).unwrap_or('0');
                if v[num_pos] != ':' {
                    break;
                }
                if num_pos == 0 || v[num_pos - 1] == '.' {
                    v[num_pos] = 'a';
                    break;
                } else {
                    v[num_pos] = '0';
                    num_pos -= 1;
                }
            }
        }
    }
    *arc_name = v.into_iter().collect();
}

pub fn is_name_usable(name: &str) -> bool {
    let v = chars(name);
    if cfg!(unix) {
        if name.contains(':') {
            return false;
        }
    } else if v.iter().skip(2).any(|&c| c == ':') {
        return false;
    }
    for i in 0..v.len() {
        if (v[i] as u32) < 32 {
            return false;
        }
        if cfg!(unix) && (v[i] == ' ' || v[i] == '.') && is_path_div(at(&v, i + 1)) {
            return false;
        }
    }
    !name.is_empty() && !v.iter().any(|c| "?*<>|\"".contains(*c))
}

pub fn make_name_usable(name: &mut String, extended: bool) {
    let mut v = chars(name);
    for i in 0..v.len() {
        let bad = if extended { "?*<>|\"" } else { "?*" };
        if bad.contains(v[i]) || extended && (v[i] as u32) < 32 {
            v[i] = '_';
        }
        if cfg!(unix) {
            if extended {
                if v[i] == ':' {
                    v[i] = '_';
                }
                if is_path_div(at(&v, i + 1))
                    && (v[i] == ' '
                        || v[i] == '.'
                            && i > 0
                            && !is_path_div(v[i - 1])
                            && (v[i - 1] != '.' || i > 1 && !is_path_div(v[i - 2])))
                {
                    v[i] = '_';
                }
            }
        } else if i > 1 && v[i] == ':' {
            v[i] = '_';
        }
    }
    *name = v.into_iter().collect();
}

pub fn unix_slash_to_dos(s: &str) -> String {
    s.replace('/', "\\")
}

pub fn dos_slash_to_unix(s: &str) -> String {
    s.replace('\\', "/")
}

/// Convert both slash types to native path separator.
pub fn slash_to_native(s: &str) -> String {
    if cfg!(unix) {
        dos_slash_to_unix(s)
    } else {
        unix_slash_to_dos(s)
    }
}

pub fn is_full_path(path: &str) -> bool {
    let v = chars(path);
    if cfg!(unix) {
        !v.is_empty() && is_path_div(v[0])
    } else {
        v.len() >= 2 && v[0] == '\\' && v[1] == '\\' || v.len() >= 3 && is_drive_letter(path) && is_path_div(v[2])
    }
}

pub fn is_full_root_path(path: &str) -> bool {
    is_full_path(path) || path.chars().next().map(is_path_div).unwrap_or(false)
}

pub fn convert_name_to_full(src: &str) -> String {
    if src.is_empty() {
        return String::new();
    }
    if is_full_path(src) {
        return src.to_string();
    }
    let mut d = std::env::current_dir().map(|p| crate::unicode::from_os(p.as_os_str())).unwrap_or_default();
    add_end_slash(&mut d);
    d + src
}

/// Parse "name;ver" version suffix. Returns version and optionally truncates.
pub fn parse_version_file_name(name: &mut String, truncate: bool) -> i32 {
    let mut version = 0;
    if let Some(p) = name.rfind(';') {
        if p + 1 < name.len() {
            version = atoiw(&name[p + 1..]) as i32;
            if truncate {
                name.truncate(p);
            }
        }
    }
    version
}

/// Get the name of first volume. Returns name and the leftmost digit
/// position of volume number.
pub fn vol_name_to_first_name(vol_name: &str, new_numbering: bool) -> (String, usize) {
    let mut v = chars(vol_name);
    let mut vol_num_start = 0;
    let mut name;
    if new_numbering {
        let mut n = '1';
        let mut pos = get_vol_num_pos(&v);
        while pos > 0 {
            if v[pos].is_ascii_digit() {
                v[pos] = n;
                n = '0';
            } else if n == '0' {
                vol_num_start = pos + 1;
                break;
            }
            pos -= 1;
        }
        name = v.into_iter().collect::<String>();
    } else {
        name = vol_name.to_string();
        set_ext(&mut name, "rar");
        vol_num_start = get_ext_pos(&name).unwrap_or(0);
    }
    if !crate::filefn::file_exist(&name) {
        let mut mask = name.clone();
        set_ext(&mut mask, "*");
        let mut find = crate::find::FindFile::new();
        find.set_mask(&mask);
        let mut fd = crate::find::FindData::default();
        while find.next(&mut fd, false) {
            let cmd = std::rc::Rc::new(std::cell::RefCell::new(crate::cmddata::CommandData::new()));
            let mut arc = crate::archive::Archive::new(cmd);
            if arc.open(&fd.name, 0) && arc.is_archive(true) && arc.first_volume {
                name = fd.name.clone();
                break;
            }
        }
    }
    (name, vol_num_start)
}

fn gen_arc_name(arc_name: &mut String, generate_mask: &str, arc_number: u32, arc_num_present: &mut bool) {
    use crate::strfn::{get_digits, toupperw};
    let gm = chars(generate_mask);
    let mut pos = 0;
    let mut prefix = false;
    if at(&gm, 0) == '+' {
        prefix = true;
        pos += 1;
    }
    let mut mask: Vec<char> = if gm.len() > pos { gm[pos..].to_vec() } else { chars("yyyymmddhhmmss") };
    let mut quote = false;
    let mut m_as_minutes = 0;
    let mut i = 0;
    while i < mask.len() {
        if mask[i] == '{' || mask[i] == '}' {
            quote = mask[i] == '{';
            i += 1;
            continue;
        }
        if quote {
            i += 1;
            continue;
        }
        let cur = toupperw(mask[i]);
        if cur == 'H' {
            m_as_minutes = 2;
        }
        if cur == 'D' || cur == 'Y' {
            m_as_minutes = 0;
        }
        if cur == 'M' {
            if m_as_minutes > 0 {
                mask[i] = 'I';
                m_as_minutes -= 1;
            } else if i + 2 < mask.len() && toupperw(mask[i + 1]) == 'M' && toupperw(mask[i + 2]) == 'M' {
                let mut j = i;
                while j < mask.len() && toupperw(mask[j]) == 'M' {
                    mask[j] = 'O';
                    j += 1;
                }
            }
        }
        if cur == 'N' {
            let digits = get_digits(arc_number) as usize;
            let mut ncount = 0;
            while toupperw(at(&mask, i + ncount)) == 'N' {
                ncount += 1;
            }
            if ncount < digits {
                for _ in 0..digits - ncount {
                    mask.insert(i, 'N');
                }
            }
            i += digits.max(ncount) - 1;
            *arc_num_present = true;
            i += 1;
            continue;
        }
        i += 1;
    }
    let mut cur_time = crate::timefn::RarTime::default();
    cur_time.set_current_time();
    let rlt = cur_time.get_local();
    let ext;
    match get_ext_pos(arc_name) {
        None => ext = if point_to_name(arc_name).is_empty() { ".rar".to_string() } else { String::new() },
        Some(p) => {
            ext = arc_name[p..].to_string();
            arc_name.truncate(p);
        }
    }
    let week_day: i32 = if rlt.wday == 0 { 6 } else { rlt.wday as i32 - 1 };
    let mut start_week_day = rlt.yday as i32 - week_day;
    if start_week_day < 0 {
        if start_week_day <= -4 {
            start_week_day += if crate::timefn::is_leap_year(rlt.year - 1) { 366 } else { 365 };
        } else {
            start_week_day = 0;
        }
    }
    let mut cur_week = start_week_day / 7 + 1;
    if start_week_day % 7 >= 4 {
        cur_week += 1;
    }
    let field: Vec<Vec<char>> = vec![
        chars(&format!("{:04}", rlt.year)),
        chars(&format!("{:02}", rlt.month)),
        chars(&format!("{:02}", rlt.day)),
        chars(&format!("{:02}", rlt.hour)),
        chars(&format!("{:02}", rlt.minute)),
        chars(&format!("{:02}", rlt.second)),
        chars(&format!("{:02}", cur_week)),
        chars(&format!("{}", week_day + 1)),
        chars(&format!("{:03}", rlt.yday + 1)),
        chars(&format!("{:05}", arc_number)),
        chars(crate::ui::ui_get_week_day_name(rlt.wday)).into_iter().take(19).collect(),
        chars(crate::ui::ui_get_month_name(rlt.month - 1)).into_iter().take(19).collect(),
    ];
    let lfield: Vec<i32> = field.iter().map(|f| f.len() as i32).collect();
    let mask_chars = chars("YMDHISWAENKO");
    let mask_align = chars("RRRRRRRRRRLL");
    let mut cfield = [0i32; 12];
    quote = false;
    for &c in &mask {
        if c == '{' || c == '}' {
            quote = c == '{';
            continue;
        }
        if quote {
            continue;
        }
        if let Some(fp) = mask_chars.iter().position(|&m| m == toupperw(c)) {
            if mask_align[fp] == 'R' && cfield[fp] < lfield[fp] {
                cfield[fp] += 1;
            }
        }
    }
    let mut date_text = String::new();
    quote = false;
    for &c in &mask {
        if date_text.chars().count() >= 127 {
            break;
        }
        if c == '{' || c == '}' {
            quote = c == '{';
            continue;
        }
        let fp = mask_chars.iter().position(|&m| m == toupperw(c));
        match fp {
            Some(fp) if !quote => {
                if mask_align[fp] == 'L' {
                    if cfield[fp] < lfield[fp] {
                        date_text.push(field[fp][cfield[fp] as usize]);
                        cfield[fp] += 1;
                    }
                } else if cfield[fp] >= 0 {
                    let idx = lfield[fp] - cfield[fp];
                    cfield[fp] -= 1;
                    if let Some(&ch) = field[fp].get(idx as usize) {
                        date_text.push(ch);
                    }
                }
            }
            _ => {
                let ch = if !cfg!(unix) && c == ':' { '_' } else { c };
                date_text.push(ch);
            }
        }
    }
    if prefix {
        let mut new_name = get_path_with_sep(arc_name);
        new_name.push_str(&date_text);
        new_name.push_str(point_to_name(arc_name));
        *arc_name = new_name;
    } else {
        arc_name.push_str(&date_text);
    }
    arc_name.push_str(&ext);
}

pub fn generate_archive_name(arc_name: &mut String, generate_mask: &str, archiving: bool) {
    let mut arc_number = 1;
    let mut new_name;
    loop {
        new_name = arc_name.clone();
        let mut present = false;
        gen_arc_name(&mut new_name, generate_mask, arc_number, &mut present);
        if !present {
            break;
        }
        if !crate::filefn::file_exist(&new_name) {
            if !archiving && arc_number > 1 {
                new_name = arc_name.clone();
                gen_arc_name(&mut new_name, generate_mask, arc_number - 1, &mut present);
            }
            break;
        }
        arc_number += 1;
    }
    *arc_name = new_name;
}

/// Enumerate configuration file paths.
pub fn enum_config_paths(number: u32) -> Option<String> {
    const CONF: [&str; 5] = ["/etc", "/etc/rar", "/usr/lib", "/usr/local/lib", "/usr/local/etc"];
    let home = std::env::var_os("HOME").map(|h| crate::unicode::from_os(&h));
    if number == 0 {
        return Some(home.unwrap_or_else(|| CONF[0].to_string()));
    }
    if number == 1 {
        if let Some(x) = std::env::var_os("XDG_CONFIG_HOME") {
            if !x.is_empty() {
                return Some(make_name(&crate::unicode::from_os(&x), "rar"));
            }
        }
        return Some(match home {
            Some(h) => make_name(&h, ".config/rar"),
            None => CONF[0].to_string(),
        });
    }
    CONF.get((number - 2) as usize).map(|s| s.to_string())
}

pub fn get_config_name(name: &str, check_exist: bool) -> String {
    let mut full = String::new();
    let mut i = 0;
    while let Some(p) = enum_config_paths(i) {
        full = make_name(&p, name);
        if !check_exist || crate::filefn::wild_file_exist(&full) {
            break;
        }
        i += 1;
    }
    full
}

/// Make the name acceptable for Windows: replace trailing dots and spaces
/// in path components and prefix reserved device names with '_'.
pub fn make_name_compatible(name: &mut String) {
    let mut v = chars(name);
    let n = v.len();
    for i in 0..n {
        if i + 1 == n || is_path_div(v[i + 1]) {
            let c = v[i];
            if c == '.' || c == ' ' {
                if c == '.' {
                    let drive = is_drive_letter(name);
                    if i == 0 || is_path_div(v[i - 1]) || i == 2 && drive {
                        continue;
                    }
                    if i >= 1 && v[i - 1] == '.' && (i == 1 || is_path_div(v[i - 2]) || i == 3 && drive) {
                        continue;
                    }
                }
                v[i] = '_';
            }
        }
    }
    const DEVICES: [&str; 6] = ["CON", "PRN", "AUX", "NUL", "COM#", "LPT#"];
    let mut i = 0;
    while i < v.len() {
        if i == 0 || is_path_div(v[i - 1]) {
            let mut found = false;
            for d in DEVICES {
                let dc: Vec<char> = d.chars().collect();
                let mut k = 0;
                let mut ok = true;
                while k < dc.len() {
                    let c = at(&v, i + k);
                    if dc[k] == '#' {
                        if !c.is_ascii_digit() {
                            ok = false;
                            break;
                        }
                    } else if dc[k] != c.to_ascii_uppercase() {
                        ok = false;
                        break;
                    }
                    k += 1;
                }
                if ok {
                    let c = at(&v, i + k);
                    // Names like aux.txt are accessible in Windows 11, pure aux is not.
                    if c == '\0' || is_path_div(c) {
                        found = true;
                        break;
                    }
                }
            }
            if found {
                let orig: String = v.iter().collect();
                v.insert(i, '_');
                let new: String = v.iter().collect();
                crate::ui::ui_msg(crate::ui::UiMsg::CorrectingName(String::new()));
                crate::ui::ui_msg(crate::ui::UiMsg::Renaming(String::new(), orig, new));
                i += 1;
            }
        }
        i += 1;
    }
    *name = v.into_iter().collect();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn volumes() {
        let mut n = "arc.part1.rar".to_string();
        next_volume_name(&mut n, false);
        assert_eq!(n, "arc.part2.rar");
        let mut n = "arc.part9.rar".to_string();
        next_volume_name(&mut n, false);
        assert_eq!(n, "arc.part10.rar");
        let mut n = "arc.rar".to_string();
        next_volume_name(&mut n, true);
        assert_eq!(n, "arc.r00");
        next_volume_name(&mut n, true);
        assert_eq!(n, "arc.r01");
        let mut n = "arc.r99".to_string();
        next_volume_name(&mut n, true);
        assert_eq!(n, "arc.s00");
    }
    #[test]
    fn convert() {
        assert_eq!(convert_path("../../a/b").1, "a/b");
        assert_eq!(convert_path("/abs/x").1, "abs/x");
        assert_eq!(convert_path("a/../b").1, "b");
    }
}
