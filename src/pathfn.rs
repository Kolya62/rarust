// SPDX-License-Identifier: GPL-3.0-or-later

//! File name and path helpers: name and extension parts, volume names,
//! sanitizing names from archives, and archive names generated from the
//! current date.

use crate::strfn::{atoiw, toupperw, wcsicomp_eq};

#[cfg(unix)]
pub const CPATHDIVIDER: char = '/';
#[cfg(not(unix))]
pub const CPATHDIVIDER: char = '\\';

/// Path separator of this system; Windows accepts both slashes.
pub fn is_path_div(c: char) -> bool {
    c == CPATHDIVIDER || (!cfg!(unix) && c == '/')
}

pub fn is_drive_div(c: char) -> bool {
    !cfg!(unix) && c == ':'
}

pub(crate) fn chars(s: &str) -> Vec<char> {
    s.chars().collect()
}

/// Character at `i`, or NUL past the end.
pub(crate) fn at(v: &[char], i: usize) -> char {
    v.get(i).copied().unwrap_or('\0')
}

/// "X:" at the start of the path (Windows only).
pub fn is_drive_letter(path: &str) -> bool {
    let mut c = path.chars();
    matches!((c.next(), c.next()), (Some(l), Some(d)) if l.is_ascii_alphabetic() && is_drive_div(d))
}

/// Index of the first character of the name part.
pub fn get_name_pos_c(p: &[char]) -> usize {
    match p.iter().rposition(|&c| is_path_div(c)) {
        Some(i) => i + 1,
        None if p.len() >= 2 && p[0].is_ascii_alphabetic() && is_drive_div(p[1]) => 2,
        None => 0,
    }
}

/// Byte index of the name part.
pub fn get_name_pos(path: &str) -> usize {
    match path.char_indices().rfind(|&(_, c)| is_path_div(c)) {
        Some((i, c)) => i + c.len_utf8(),
        None if is_drive_letter(path) => path.char_indices().nth(2).map_or(path.len(), |(i, _)| i),
        None => 0,
    }
}

pub fn point_to_name(path: &str) -> &str {
    &path[get_name_pos(path)..]
}

pub fn get_last_char(path: &str) -> char {
    path.chars().last().unwrap_or('\0')
}

/// Makes a path from an archive safe to use below the destination:
/// drops everything up to the last "/../" (or a trailing "/.."), then
/// any drive, UNC "//server/share/" and leading separators and dots, and
/// finally a remaining ".." name. Returns the number of removed
/// characters and the result.
pub fn convert_path(src: &str) -> (usize, String) {
    let s = chars(src);
    let n = s.len();
    let mut start = 0;
    for i in 0..n {
        let dotdot = is_path_div(s[i]) && at(&s, i + 1) == '.' && at(&s, i + 2) == '.';
        if dotdot && (i + 3 == n || is_path_div(at(&s, i + 3))) {
            start = (i + 4).min(n);
        }
    }
    loop {
        let mut i = start;
        if i + 1 < n && is_drive_div(s[i + 1]) {
            i += 2;
        }
        if is_path_div(at(&s, i)) && is_path_div(at(&s, i + 1)) {
            // Skip "\\server\share\".
            if let Some(k) = s[i + 2..].iter().enumerate().filter(|&(_, &c)| is_path_div(c)).nth(1).map(|(k, _)| k) {
                i += 2 + k + 1;
            }
        }
        // Leading separators and dots, up to the last separator among them.
        for (j, &c) in s.iter().enumerate().skip(i) {
            if is_path_div(c) {
                i = j + 1;
            } else if c != '.' {
                break;
            }
        }
        if i == start || start >= n {
            break;
        }
        start = i;
    }
    let mut start = start.min(n);
    if n - start == 2 && s[start] == '.' && s[start + 1] == '.' {
        start = n;
    }
    (start, s[start..].iter().collect())
}

pub fn set_name(full: &mut String, name: &str) {
    full.truncate(get_name_pos(full));
    full.push_str(name);
}

/// Byte position of the extension dot in the name part.
pub fn get_ext_pos(name: &str) -> Option<usize> {
    name.rfind('.').filter(|&d| d >= get_name_pos(name))
}

/// Extension including the dot, or "".
pub fn get_ext(name: &str) -> &str {
    get_ext_pos(name).map_or("", |p| &name[p..])
}

pub fn set_ext(name: &mut String, ext: &str) {
    remove_ext(name);
    name.push('.');
    name.push_str(ext);
}

pub fn remove_ext(name: &mut String) {
    if let Some(p) = get_ext_pos(name) {
        name.truncate(p);
    }
}

/// Extension (without the dot) equals `ext`, ignoring case.
pub fn cmp_ext(name: &str, ext: &str) -> bool {
    match get_ext_pos(name) {
        None => ext.is_empty(),
        Some(p) => wcsicomp_eq(&name[p + 1..], ext),
    }
}

pub fn is_wildcard(s: &str) -> bool {
    s.contains(['*', '?'])
}

pub fn add_end_slash(path: &mut String) {
    if !path.is_empty() && !path.ends_with(CPATHDIVIDER) {
        path.push(CPATHDIVIDER);
    }
}

/// `path` + separator + `name`; a bare drive "X:" gets no separator.
pub fn make_name(path: &str, name: &str) -> String {
    let mut out = path.to_string();
    if !(is_drive_letter(path) && path.chars().count() == 2) {
        add_end_slash(&mut out);
    }
    out + name
}

/// Path part including the trailing separator.
pub fn get_path_with_sep(full: &str) -> String {
    full[..get_name_pos(full)].to_string()
}

/// Leaves the path without the name and its separator, keeping the root
/// separator of "/name" and "X:\name".
pub fn remove_name_from_path(path: &mut String) {
    let v = chars(path);
    let mut np = get_name_pos_c(&v);
    if np >= 2 && (!is_drive_div(v[1]) || np >= 4) {
        np -= 1;
    }
    let byte = path.char_indices().nth(np).map_or(path.len(), |(i, _)| i);
    path.truncate(byte);
}

/// Position of the last digit of the volume number in "name.partNN.rar"
/// style names: normally the last digit of the name part.
pub fn get_vol_num_pos(arc: &[char]) -> usize {
    let start = get_name_pos_c(arc);
    if start == arc.len() {
        return start;
    }
    // Last digit of the name (or the start of the name if none).
    let mut last = arc.len() - 1;
    while last > start && !arc[last].is_ascii_digit() {
        last -= 1;
    }
    // Skip that digit group.
    let mut p = last;
    while p > start && arc[p].is_ascii_digit() {
        p -= 1;
    }
    // A digit group before it, within the same dot separated part, wins
    // if the name has a dot before that group ("a.part1b2.rar" style
    // names keep the first group).
    while p > start && arc[p] != '.' {
        if arc[p].is_ascii_digit() {
            if arc[start..].iter().position(|&c| c == '.').is_some_and(|d| start + d < p) {
                last = p;
            }
            break;
        }
        p -= 1;
    }
    last
}

/// Name of the next volume: "name.partN.rar" with the number increased,
/// or for old style numbering .rar, .r00 ... .r99, .s00 ...
pub fn next_volume_name(arc_name: &mut String, old_numbering: bool) {
    match get_ext_pos(arc_name) {
        None => arc_name.push_str(".rar"),
        Some(p) if p + 1 == arc_name.len() || cmp_ext(arc_name, "exe") || cmp_ext(arc_name, "sfx") => {
            set_ext(arc_name, "rar")
        }
        _ => {}
    }
    let dot_byte = get_ext_pos(arc_name).unwrap();
    let dot = arc_name[..dot_byte].chars().count();
    let mut v = chars(arc_name);
    if !old_numbering {
        // Decimal increment; a carry out of the leftmost digit inserts 1.
        let mut i = get_vol_num_pos(&v);
        loop {
            if v[i] == '9' {
                v[i] = '0';
                if i == 0 {
                    break;
                }
                i -= 1;
                if !v[i].is_ascii_digit() {
                    v.insert(i + 1, '1');
                    break;
                }
            } else {
                v[i] = char::from_u32(v[i] as u32 + 1).unwrap_or('0');
                break;
            }
        }
    } else {
        if v.len() - dot < 3 {
            v.truncate(dot + 1);
            v.extend("rar".chars());
        }
        if !at(&v, dot + 2).is_ascii_digit() || !at(&v, dot + 3).is_ascii_digit() {
            // .rar -> .r00
            v.truncate(dot + 2);
            v.extend("00".chars());
        } else {
            // Increment the digits; .r99 continues with the next letter.
            let mut i = v.len() - 1;
            loop {
                if v[i] != '9' {
                    v[i] = char::from_u32(v[i] as u32 + 1).unwrap_or('0');
                    break;
                }
                if i == 0 || v[i - 1] == '.' {
                    v[i] = 'a';
                    break;
                }
                v[i] = '0';
                i -= 1;
            }
        }
    }
    *arc_name = v.into_iter().collect();
}

/// Name can be created as is in this file system.
pub fn is_name_usable(name: &str) -> bool {
    let v = chars(name);
    let colon = if cfg!(unix) { v.contains(&':') } else { v.iter().skip(2).any(|&c| c == ':') };
    if name.is_empty() || colon || v.iter().any(|&c| (c as u32) < 32 || "?*<>|\"".contains(c)) {
        return false;
    }
    // Trailing spaces and dots in path components are trouble for
    // Windows tools even on Unix.
    !(cfg!(unix) && v.windows(2).any(|w| (w[0] == ' ' || w[0] == '.') && is_path_div(w[1])))
}

/// Replaces characters that cannot be used in names by '_'. `extended`
/// also handles control characters and characters invalid in Windows.
pub fn make_name_usable(name: &mut String, extended: bool) {
    let mut v = chars(name);
    let bad = if extended { "?*<>|\"" } else { "?*" };
    for i in 0..v.len() {
        let c = v[i];
        let mut replace = bad.contains(c) || (extended && (c as u32) < 32);
        if cfg!(unix) {
            if extended {
                replace |= c == ':';
                // Trailing space or dot of a component, except "." and "..".
                let before_div = is_path_div(at(&v, i + 1));
                let lone_dot = i == 0 || is_path_div(v[i - 1]);
                let dot_dot = v[i - i.min(1)] == '.' && (i == 1 || (i > 1 && is_path_div(v[i - 2])));
                if before_div && (c == ' ' || (c == '.' && !lone_dot && !dot_dot)) {
                    replace = true;
                }
            }
        } else if i > 1 && c == ':' {
            replace = true;
        }
        if replace {
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

pub fn slash_to_native(s: &str) -> String {
    if cfg!(unix) {
        dos_slash_to_unix(s)
    } else {
        unix_slash_to_dos(s)
    }
}

/// Absolute path: "/..." on Unix, "\\server..." or "X:\..." on Windows.
pub fn is_full_path(path: &str) -> bool {
    let v = chars(path);
    if cfg!(unix) {
        v.first().is_some_and(|&c| is_path_div(c))
    } else {
        v.starts_with(&['\\', '\\']) || (v.len() >= 3 && is_drive_letter(path) && is_path_div(v[2]))
    }
}

/// Absolute path or a path from the root of the current drive.
pub fn is_full_root_path(path: &str) -> bool {
    is_full_path(path) || path.chars().next().is_some_and(is_path_div)
}

pub fn convert_name_to_full(src: &str) -> String {
    if src.is_empty() || is_full_path(src) {
        return src.to_string();
    }
    let mut d = std::env::current_dir().map(|p| crate::unicode::from_os(p.as_os_str())).unwrap_or_default();
    add_end_slash(&mut d);
    d + src
}

/// Version of "name;N" file names; with `truncate` the suffix is removed.
pub fn parse_version_file_name(name: &mut String, truncate: bool) -> i32 {
    match name.rfind(';') {
        Some(p) if p + 1 < name.len() => {
            let v = atoiw(&name[p + 1..]) as i32;
            if truncate {
                name.truncate(p);
            }
            v
        }
        _ => 0,
    }
}

/// Name of the first volume of a volume set, and the position of the
/// leftmost digit of the volume number. If that file does not exist, the
/// directory is searched for a first volume with the same base name.
pub fn vol_name_to_first_name(vol_name: &str, new_numbering: bool) -> (String, usize) {
    let mut num_start = 0;
    let mut name = if new_numbering {
        // Replace the number by 1, 01, 001...
        let mut v = chars(vol_name);
        let mut digit = '1';
        let mut pos = get_vol_num_pos(&v);
        while pos > 0 {
            if v[pos].is_ascii_digit() {
                v[pos] = digit;
                digit = '0';
            } else if digit == '0' {
                num_start = pos + 1;
                break;
            }
            pos -= 1;
        }
        v.into_iter().collect()
    } else {
        let mut n = vol_name.to_string();
        set_ext(&mut n, "rar");
        num_start = get_ext_pos(&n).unwrap_or(0);
        n
    };
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
    (name, num_start)
}

/// Date fields of archive name masks: letter, value, alignment. Right
/// aligned fields take their last characters when the mask repeats the
/// letter fewer times than the field is long; left aligned (names) take
/// the first ones.
struct DateField {
    letter: char,
    text: Vec<char>,
    right: bool,
}

/// Expands an archive name mask like "yyyymmdd" or "+{arc}nnn". Letters:
/// Y year, M month (or minutes after H), D day, H hour, I minutes, S
/// seconds, W week, A weekday number, E day of year, N archive number,
/// K weekday name, O month name ("MMM" or longer). "{...}" is literal
/// text; a leading "+" puts the date before the name.
fn gen_arc_name(arc_name: &mut String, generate_mask: &str, arc_number: u32, has_number: &mut bool) {
    let (prefix, mask) = match generate_mask.strip_prefix('+') {
        Some(m) => (true, m),
        None => (false, generate_mask),
    };
    let mut mask = chars(if mask.is_empty() { "yyyymmddhhmmss" } else { mask });

    // Normalize letters: minutes, month names and enough N for the number.
    let mut quoted = false;
    let mut minutes_left = 0;
    let mut i = 0;
    while i < mask.len() {
        let c = mask[i];
        if c == '{' || c == '}' {
            quoted = c == '{';
            i += 1;
            continue;
        }
        if quoted {
            i += 1;
            continue;
        }
        match toupperw(c) {
            'H' => minutes_left = 2,
            'D' | 'Y' => minutes_left = 0,
            _ => {}
        }
        match toupperw(c) {
            'M' if minutes_left > 0 => {
                mask[i] = 'I';
                minutes_left -= 1;
            }
            'M' if (1..3).all(|k| toupperw(at(&mask, i + k)) == 'M') => {
                let mut j = i;
                while j < mask.len() && toupperw(mask[j]) == 'M' {
                    mask[j] = 'O';
                    j += 1;
                }
            }
            'N' => {
                let digits = crate::strfn::get_digits(arc_number) as usize;
                let run = mask[i..].iter().take_while(|&&c| toupperw(c) == 'N').count();
                for _ in run..digits {
                    mask.insert(i, 'N');
                }
                i += digits.max(run);
                *has_number = true;
                continue;
            }
            _ => {}
        }
        i += 1;
    }

    let mut now = crate::timefn::RarTime::default();
    now.set_current_time();
    let t = now.get_local();
    let ext = match get_ext_pos(arc_name) {
        Some(p) => {
            let e = arc_name[p..].to_string();
            arc_name.truncate(p);
            e
        }
        None if point_to_name(arc_name).is_empty() => ".rar".to_string(),
        None => String::new(),
    };
    // ISO 8601 week: weeks start on Monday, week 1 has the year's first
    // Thursday.
    let weekday = if t.wday == 0 { 6 } else { t.wday as i32 - 1 };
    let mut week_start = t.yday as i32 - weekday;
    if week_start < 0 {
        week_start = if week_start <= -4 {
            week_start + if crate::timefn::is_leap_year(t.year - 1) { 366 } else { 365 }
        } else {
            0
        };
    }
    let week = week_start / 7 + 1 + (week_start % 7 >= 4) as i32;
    let name_field = |s: &str| s.chars().take(19).collect::<Vec<char>>();
    let mut fields = [
        DateField { letter: 'Y', text: chars(&format!("{:04}", t.year)), right: true },
        DateField { letter: 'M', text: chars(&format!("{:02}", t.month)), right: true },
        DateField { letter: 'D', text: chars(&format!("{:02}", t.day)), right: true },
        DateField { letter: 'H', text: chars(&format!("{:02}", t.hour)), right: true },
        DateField { letter: 'I', text: chars(&format!("{:02}", t.minute)), right: true },
        DateField { letter: 'S', text: chars(&format!("{:02}", t.second)), right: true },
        DateField { letter: 'W', text: chars(&format!("{week:02}")), right: true },
        DateField { letter: 'A', text: chars(&format!("{}", weekday + 1)), right: true },
        DateField { letter: 'E', text: chars(&format!("{:03}", t.yday + 1)), right: true },
        DateField { letter: 'N', text: chars(&format!("{arc_number:05}")), right: true },
        DateField { letter: 'K', text: name_field(crate::ui::ui_get_week_day_name(t.wday)), right: false },
        DateField { letter: 'O', text: name_field(crate::ui::ui_get_month_name(t.month - 1)), right: false },
    ];
    let field_of = |c: char, fields: &[DateField]| fields.iter().position(|f| f.letter == toupperw(c));

    // For right aligned fields count how many characters the mask wants.
    let mut used = [0usize; 12];
    let mut quoted = false;
    for &c in &mask {
        if c == '{' || c == '}' {
            quoted = c == '{';
        } else if !quoted {
            if let Some(f) = field_of(c, &fields) {
                if fields[f].right && used[f] < fields[f].text.len() {
                    used[f] += 1;
                }
            }
        }
    }
    let mut text = String::new();
    let mut quoted = false;
    let mut taken = [0usize; 12];
    for &c in &mask {
        if text.chars().count() >= 127 {
            break;
        }
        if c == '{' || c == '}' {
            quoted = c == '{';
            continue;
        }
        match field_of(c, &fields).filter(|_| !quoted) {
            Some(f) => {
                let fd = &mut fields[f];
                if fd.right {
                    // The last `used` characters of the field, then nothing.
                    let idx = fd.text.len() as isize - (used[f] as isize - taken[f] as isize);
                    taken[f] += 1;
                    if idx >= 0 {
                        if let Some(&ch) = fd.text.get(idx as usize) {
                            text.push(ch);
                        }
                    }
                } else if taken[f] < fd.text.len() {
                    text.push(fd.text[taken[f]]);
                    taken[f] += 1;
                }
            }
            None => text.push(if !cfg!(unix) && c == ':' { '_' } else { c }),
        }
    }
    if prefix {
        let n = point_to_name(arc_name).to_string();
        *arc_name = get_path_with_sep(arc_name) + &text + &n;
    } else {
        arc_name.push_str(&text);
    }
    arc_name.push_str(&ext);
}

/// Applies a name mask, choosing the first unused archive number if the
/// mask has one (the last existing one when not archiving).
pub fn generate_archive_name(arc_name: &mut String, generate_mask: &str, archiving: bool) {
    let mut number = 1;
    loop {
        let mut name = arc_name.clone();
        let mut has_number = false;
        gen_arc_name(&mut name, generate_mask, number, &mut has_number);
        if !has_number {
            *arc_name = name;
            return;
        }
        if !crate::filefn::file_exist(&name) {
            if !archiving && number > 1 {
                name = arc_name.clone();
                gen_arc_name(&mut name, generate_mask, number - 1, &mut has_number);
            }
            *arc_name = name;
            return;
        }
        number += 1;
    }
}

/// Directories searched for configuration files, in order.
pub fn enum_config_paths(number: u32) -> Option<String> {
    const SYSTEM: [&str; 5] = ["/etc", "/etc/rar", "/usr/lib", "/usr/local/lib", "/usr/local/etc"];
    let home = std::env::var_os("HOME").map(|h| crate::unicode::from_os(&h));
    match number {
        0 => Some(home.unwrap_or_else(|| SYSTEM[0].to_string())),
        1 => {
            let xdg = std::env::var_os("XDG_CONFIG_HOME").filter(|x| !x.is_empty());
            Some(match (xdg, home) {
                (Some(x), _) => make_name(&crate::unicode::from_os(&x), "rar"),
                (None, Some(h)) => make_name(&h, ".config/rar"),
                (None, None) => SYSTEM[0].to_string(),
            })
        }
        n => SYSTEM.get(n as usize - 2).map(|s| s.to_string()),
    }
}

/// First configuration path containing `name` (or the last candidate).
pub fn get_config_name(name: &str, check_exist: bool) -> String {
    let mut full = String::new();
    for p in (0..).map_while(enum_config_paths) {
        full = make_name(&p, name);
        if !check_exist || crate::filefn::wild_file_exist(&full) {
            break;
        }
    }
    full
}

/// Adapts a name for Windows: trailing dots and spaces of components
/// become '_' (except "." and ".."), and reserved device names like
/// "CON" or "COM1" get a '_' prefix.
pub fn make_name_compatible(name: &mut String) {
    let drive = is_drive_letter(name);
    let mut v = chars(name);
    let n = v.len();
    for i in 0..n {
        let c = v[i];
        if !(i + 1 == n || is_path_div(v[i + 1])) || (c != '.' && c != ' ') {
            continue;
        }
        if c == '.' {
            let component_start = |k: usize| k == 0 || is_path_div(v[k - 1]) || (k == 2 && drive);
            if component_start(i) || (i >= 1 && v[i - 1] == '.' && component_start(i - 1)) {
                continue;
            }
        }
        v[i] = '_';
    }
    const DEVICES: [&str; 6] = ["CON", "PRN", "AUX", "NUL", "COM#", "LPT#"];
    let is_device = |v: &[char], i: usize| {
        DEVICES.iter().any(|d| {
            let ok = d.chars().enumerate().all(|(k, dc)| {
                let c = at(v, i + k);
                if dc == '#' {
                    c.is_ascii_digit()
                } else {
                    c.to_ascii_uppercase() == dc
                }
            });
            // "aux.txt" works in Windows 11, "aux" alone does not.
            let after = at(v, i + d.len());
            ok && (after == '\0' || is_path_div(after))
        })
    };
    let mut i = 0;
    while i < v.len() {
        if (i == 0 || is_path_div(v[i - 1])) && is_device(&v, i) {
            let orig: String = v.iter().collect();
            v.insert(i, '_');
            let new: String = v.iter().collect();
            crate::ui::ui_msg(crate::ui::UiMsg::CorrectingName(String::new()));
            crate::ui::ui_msg(crate::ui::UiMsg::Renaming(String::new(), orig, new));
            i += 1;
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
        assert_eq!(convert_path("..").1, "");
        assert_eq!(convert_path("./..").1, "");
        assert_eq!(convert_path("../").1, "");
        assert_eq!(convert_path("/..").1, "");
        assert_eq!(convert_path("..a").1, "..a");
        assert_eq!(convert_path("a..").1, "a..");
        assert_eq!(convert_path("...").1, "...");
    }
}
