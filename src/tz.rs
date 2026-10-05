// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Minimal local time zone support: TZif files and POSIX TZ rules.
//! Replaces libc localtime/mktime.

use std::sync::OnceLock;

#[derive(Clone, Debug)]
struct Rule {
    std_off: i64, // Seconds east of UTC.
    dst: Option<(i64, RuleDate, i64, RuleDate, i64)>, // dst_off, start, start_time, end, end_time
}

#[derive(Clone, Copy, Debug)]
enum RuleDate {
    Julian1(u32),       // Jn, 1..365, Feb 29 never counted.
    Julian0(u32),       // n, 0..365.
    Month(u32, u32, u32), // Mm.w.d
}

#[derive(Clone, Debug, Default)]
struct Zone {
    transitions: Vec<i64>,
    idx: Vec<u8>,
    types: Vec<i64>, // utoff per type
    footer: Option<Rule>,
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn is_leap(y: i64) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}

/// Seconds since epoch for UTC calendar fields.
pub fn timegm(y: i64, mo: u32, d: u32, h: i64, mi: i64, s: i64) -> i64 {
    days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + s
}

fn rule_date_to_time(year: i64, rd: RuleDate, time: i64, off: i64) -> i64 {
    let day = match rd {
        RuleDate::Julian1(n) => {
            let mut d = days_from_civil(year, 1, 1) + n as i64 - 1;
            if is_leap(year) && n >= 60 {
                d += 1;
            }
            d
        }
        RuleDate::Julian0(n) => days_from_civil(year, 1, 1) + n as i64,
        RuleDate::Month(m, w, wd) => {
            let first = days_from_civil(year, m, 1);
            let first_wd = (first + 4).rem_euclid(7) as u32; // 1970-01-01 is Thursday.
            let mut d = first + ((wd + 7 - first_wd) % 7) as i64 + (w as i64 - 1) * 7;
            let dim = days_from_civil(if m == 12 { year + 1 } else { year }, if m == 12 { 1 } else { m + 1 }, 1);
            while d >= dim {
                d -= 7;
            }
            d
        }
    };
    day * 86400 + time - off
}

impl Rule {
    fn offset_at(&self, t: i64) -> i64 {
        let (dst_off, s, st, e, et) = match &self.dst {
            None => return self.std_off,
            Some(x) => *x,
        };
        let (y, _, _) = civil_from_days((t + self.std_off).div_euclid(86400));
        for year in [y - 1, y, y + 1] {
            let start = rule_date_to_time(year, s, st, self.std_off);
            let end = rule_date_to_time(year, e, et, dst_off);
            if start < end {
                if t >= start && t < end {
                    return dst_off;
                }
            } else if year == y && (t >= start || t < end) {
                return dst_off;
            }
        }
        self.std_off
    }
}

fn parse_num(s: &[u8], p: &mut usize) -> Option<i64> {
    let st = *p;
    let mut n = 0i64;
    while *p < s.len() && s[*p].is_ascii_digit() {
        n = n * 10 + (s[*p] - b'0') as i64;
        *p += 1;
    }
    if *p == st {
        None
    } else {
        Some(n)
    }
}

fn parse_time(s: &[u8], p: &mut usize) -> Option<i64> {
    let mut sign = 1;
    if *p < s.len() && (s[*p] == b'+' || s[*p] == b'-') {
        if s[*p] == b'-' {
            sign = -1;
        }
        *p += 1;
    }
    let h = parse_num(s, p)?;
    let mut t = h * 3600;
    if *p < s.len() && s[*p] == b':' {
        *p += 1;
        t += parse_num(s, p)? * 60;
        if *p < s.len() && s[*p] == b':' {
            *p += 1;
            t += parse_num(s, p)?;
        }
    }
    Some(sign * t)
}

fn parse_name(s: &[u8], p: &mut usize) -> Option<()> {
    if *p < s.len() && s[*p] == b'<' {
        while *p < s.len() && s[*p] != b'>' {
            *p += 1;
        }
        if *p >= s.len() {
            return None;
        }
        *p += 1;
        return Some(());
    }
    let st = *p;
    while *p < s.len() && s[*p].is_ascii_alphabetic() {
        *p += 1;
    }
    if *p - st < 3 {
        None
    } else {
        Some(())
    }
}

fn parse_rule_date(s: &[u8], p: &mut usize) -> Option<(RuleDate, i64)> {
    let d = if *p < s.len() && s[*p] == b'M' {
        *p += 1;
        let m = parse_num(s, p)? as u32;
        if s.get(*p) != Some(&b'.') {
            return None;
        }
        *p += 1;
        let w = parse_num(s, p)? as u32;
        if s.get(*p) != Some(&b'.') {
            return None;
        }
        *p += 1;
        let d = parse_num(s, p)? as u32;
        if !(1..=12).contains(&m) || !(1..=5).contains(&w) || d > 6 {
            return None;
        }
        RuleDate::Month(m, w, d)
    } else if *p < s.len() && s[*p] == b'J' {
        *p += 1;
        RuleDate::Julian1(parse_num(s, p)? as u32)
    } else {
        RuleDate::Julian0(parse_num(s, p)? as u32)
    };
    let mut t = 7200;
    if s.get(*p) == Some(&b'/') {
        *p += 1;
        t = parse_time(s, p)?;
    }
    Some((d, t))
}

fn parse_posix(s: &str) -> Option<Rule> {
    let s = s.as_bytes();
    let mut p = 0;
    parse_name(s, &mut p)?;
    let std_off = -parse_time(s, &mut p)?;
    if p >= s.len() {
        return Some(Rule { std_off, dst: None });
    }
    parse_name(s, &mut p)?;
    let mut dst_off = std_off + 3600;
    if p < s.len() && s[p] != b',' {
        dst_off = -parse_time(s, &mut p)?;
    }
    let (sd, st, ed, et) = if s.get(p) == Some(&b',') {
        p += 1;
        let (sd, st) = parse_rule_date(s, &mut p)?;
        if s.get(p) != Some(&b',') {
            return None;
        }
        p += 1;
        let (ed, et) = parse_rule_date(s, &mut p)?;
        (sd, st, ed, et)
    } else {
        (RuleDate::Month(3, 2, 0), 7200, RuleDate::Month(11, 1, 0), 7200)
    };
    Some(Rule { std_off, dst: Some((dst_off, sd, st, ed, et)) })
}

fn be32(b: &[u8], p: usize) -> Option<i64> {
    Some(i32::from_be_bytes(b.get(p..p + 4)?.try_into().ok()?) as i64)
}

fn parse_tzif(b: &[u8]) -> Option<Zone> {
    if b.len() < 44 || &b[0..4] != b"TZif" {
        return None;
    }
    let version = b[4];
    let hdr = |p: usize| -> Option<[usize; 6]> {
        let mut c = [0usize; 6];
        for (i, v) in c.iter_mut().enumerate() {
            *v = be32(b, p + 20 + i * 4)? as usize;
        }
        Some(c)
    };
    // isutcnt, isstdcnt, leapcnt, timecnt, typecnt, charcnt
    let c1 = hdr(0)?;
    let size1 = c1[3] * 5 + c1[4] * 6 + c1[5] + c1[2] * 8 + c1[1] + c1[0];
    let (base, c, tsize) = if version >= b'2' {
        let p2 = 44 + size1;
        (p2, hdr(p2)?, 8)
    } else {
        (0, c1, 4)
    };
    let mut p = base + 44;
    let mut z = Zone::default();
    for _ in 0..c[3] {
        let t = if tsize == 8 {
            i64::from_be_bytes(b.get(p..p + 8)?.try_into().ok()?)
        } else {
            be32(b, p)?
        };
        z.transitions.push(t);
        p += tsize;
    }
    for _ in 0..c[3] {
        z.idx.push(*b.get(p)?);
        p += 1;
    }
    for _ in 0..c[4] {
        z.types.push(be32(b, p)?);
        p += 6;
    }
    p += c[5] + c[2] * (tsize + 4) + c[1] + c[0];
    if version >= b'2' && b.get(p) == Some(&b'\n') {
        let rest = &b[p + 1..];
        if let Some(e) = rest.iter().position(|&x| x == b'\n') {
            if let Ok(s) = std::str::from_utf8(&rest[..e]) {
                z.footer = parse_posix(s);
            }
        }
    }
    if z.types.is_empty() {
        return None;
    }
    Some(z)
}

impl Zone {
    fn offset_at(&self, t: i64) -> i64 {
        if self.transitions.is_empty() || t < self.transitions[0] {
            if self.transitions.is_empty() {
                if let Some(f) = &self.footer {
                    return f.offset_at(t);
                }
            }
            return self.types[0];
        }
        let i = match self.transitions.binary_search(&t) {
            Ok(i) => i,
            Err(i) => i - 1,
        };
        if i + 1 == self.transitions.len() {
            if let Some(f) = &self.footer {
                return f.offset_at(t);
            }
        }
        self.types.get(self.idx[i] as usize).copied().unwrap_or(0)
    }
}

fn load_zone() -> Zone {
    let utc = Zone { types: vec![0], ..Default::default() };
    let tz = std::env::var("TZ").ok();
    // Windows uses system time zone functions if TZ is not set.
    if cfg!(windows) && tz.as_deref().map(|s| s.is_empty()).unwrap_or(true) {
        return utc;
    }
    let path = match &tz {
        Some(s) if !s.is_empty() => {
            let s = s.strip_prefix(':').unwrap_or(s);
            if s.starts_with('/') {
                s.to_string()
            } else {
                let p = format!("/usr/share/zoneinfo/{}", s);
                if std::path::Path::new(&p).is_file() {
                    p
                } else if let Some(r) = parse_posix(s) {
                    return Zone { types: vec![r.std_off], footer: Some(r), ..Default::default() };
                } else {
                    return utc;
                }
            }
        }
        _ => "/etc/localtime".to_string(),
    };
    std::fs::read(path).ok().and_then(|b| parse_tzif(&b)).unwrap_or(utc)
}

fn zone() -> &'static Zone {
    static Z: OnceLock<Zone> = OnceLock::new();
    Z.get_or_init(load_zone)
}

/// Local UTC offset in seconds for the specified Unix time.
pub fn local_offset(t: i64) -> i64 {
    #[cfg(windows)]
    if use_system_zone() {
        return crate::win32::local_offset(t).unwrap_or(0);
    }
    zone().offset_at(t)
}

/// Windows system time zone is used unless TZ variable is set.
#[cfg(windows)]
fn use_system_zone() -> bool {
    static S: OnceLock<bool> = OnceLock::new();
    *S.get_or_init(|| std::env::var("TZ").map(|s| s.is_empty()).unwrap_or(true))
}

/// Convert local calendar time to Unix time, like mktime with tm_isdst=-1.
pub fn mktime(y: i64, mo: u32, d: u32, h: i64, mi: i64, s: i64) -> i64 {
    #[cfg(windows)]
    if use_system_zone() {
        if let Some(t) = crate::win32::local_to_unix(y, mo, d, h, mi, s) {
            return t;
        }
    }
    // Normalize month like mktime does.
    let m0 = mo as i64 - 1;
    let y = y + m0.div_euclid(12);
    let mo = (m0.rem_euclid(12) + 1) as u32;
    let base = days_from_civil(y, mo, 1) + d as i64 - 1;
    let t0 = base * 86400 + h * 3600 + mi * 60 + s;
    let off = local_offset(t0);
    let t = t0 - off;
    let off2 = local_offset(t);
    if off2 != off {
        t0 - off2
    } else {
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn civil() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(days_from_civil(2024, 2, 29)), (2024, 2, 29));
    }
    #[test]
    fn posix() {
        let r = parse_posix("EST5EDT,M3.2.0,M11.1.0").unwrap();
        // 2024-07-01 12:00 UTC is in DST.
        assert_eq!(r.offset_at(timegm(2024, 7, 1, 12, 0, 0)), -4 * 3600);
        assert_eq!(r.offset_at(timegm(2024, 1, 1, 12, 0, 0)), -5 * 3600);
        let r = parse_posix("MSK-3").unwrap();
        assert_eq!(r.offset_at(0), 3 * 3600);
    }
}
