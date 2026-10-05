// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! String helpers and a small printf-compatible formatter, so the
//! message strings with format specifiers can be used directly.

/// Printf argument.
#[derive(Clone, Debug)]
pub enum Arg {
    S(String),
    I(i64),
    U(u64),
    C(char),
}

impl From<&str> for Arg {
    fn from(s: &str) -> Arg {
        Arg::S(s.to_string())
    }
}
impl From<&String> for Arg {
    fn from(s: &String) -> Arg {
        Arg::S(s.clone())
    }
}
impl From<String> for Arg {
    fn from(s: String) -> Arg {
        Arg::S(s)
    }
}
impl From<char> for Arg {
    fn from(c: char) -> Arg {
        Arg::C(c)
    }
}
macro_rules! arg_int {
    ($($t:ty => $v:ident),*) => {$(
        impl From<$t> for Arg {
            fn from(n: $t) -> Arg { Arg::$v(n as _) }
        }
    )*};
}
arg_int!(i8 => I, i16 => I, i32 => I, i64 => I, isize => I, u8 => U, u16 => U, u32 => U, u64 => U, usize => U);

impl Arg {
    fn as_i64(&self) -> i64 {
        match self {
            Arg::I(n) => *n,
            Arg::U(n) => *n as i64,
            Arg::C(c) => *c as i64,
            Arg::S(_) => 0,
        }
    }
    fn as_u64(&self) -> u64 {
        match self {
            Arg::I(n) => *n as u64,
            Arg::U(n) => *n,
            Arg::C(c) => *c as u64,
            Arg::S(_) => 0,
        }
    }
}

/// Format a printf style string.
pub fn sprintf(fmt: &str, args: &[Arg]) -> String {
    let f: Vec<char> = fmt.chars().collect();
    let mut out = String::new();
    let mut ai = 0;
    let mut i = 0;
    while i < f.len() {
        let c = f[i];
        if c != '%' {
            out.push(c);
            i += 1;
            continue;
        }
        i += 1;
        if i < f.len() && f[i] == '%' {
            out.push('%');
            i += 1;
            continue;
        }
        let mut left = false;
        let mut zero = false;
        while i < f.len() && (f[i] == '-' || f[i] == '0' || f[i] == '+' || f[i] == ' ' || f[i] == '#') {
            if f[i] == '-' {
                left = true;
            }
            if f[i] == '0' {
                zero = true;
            }
            i += 1;
        }
        let mut width = 0usize;
        while i < f.len() && f[i].is_ascii_digit() {
            width = width * 10 + f[i] as usize - '0' as usize;
            i += 1;
        }
        let mut prec: Option<usize> = None;
        if i < f.len() && f[i] == '.' {
            i += 1;
            let mut p = 0;
            while i < f.len() && f[i].is_ascii_digit() {
                p = p * 10 + f[i] as usize - '0' as usize;
                i += 1;
            }
            prec = Some(p);
        }
        while i < f.len() && (f[i] == 'l' || f[i] == 'h' || f[i] == 'z' || f[i] == 'L') {
            i += 1;
        }
        if i >= f.len() {
            break;
        }
        let conv = f[i];
        i += 1;
        let arg = args.get(ai).cloned().unwrap_or(Arg::S(String::new()));
        ai += 1;
        let (body, numeric) = match conv {
            's' => {
                let s = match arg {
                    Arg::S(s) => s,
                    Arg::C(c) => c.to_string(),
                    a => a.as_i64().to_string(),
                };
                let s = match prec {
                    Some(p) => s.chars().take(p).collect(),
                    None => s,
                };
                (s, false)
            }
            'c' => {
                let ch = match arg {
                    Arg::C(c) => c,
                    a => char::from_u32(a.as_u64() as u32).unwrap_or('?'),
                };
                (ch.to_string(), false)
            }
            'd' | 'i' => {
                let mut s = arg.as_i64().to_string();
                if let Some(p) = prec {
                    let neg = s.starts_with('-');
                    let digits = if neg { &s[1..] } else { &s[..] };
                    if digits.len() < p {
                        let pad = "0".repeat(p - digits.len());
                        s = if neg { format!("-{}{}", pad, digits) } else { format!("{}{}", pad, digits) };
                    }
                }
                (s, true)
            }
            'u' => (pad_prec(arg.as_u64().to_string(), prec), true),
            'x' => (pad_prec(format!("{:x}", arg.as_u64()), prec), true),
            'X' => (pad_prec(format!("{:X}", arg.as_u64()), prec), true),
            _ => (String::new(), false),
        };
        let len = body.chars().count();
        if len >= width {
            out.push_str(&body);
        } else if left {
            out.push_str(&body);
            out.push_str(&" ".repeat(width - len));
        } else if zero && numeric && prec.is_none() {
            if let Some(rest) = body.strip_prefix('-') {
                out.push('-');
                out.push_str(&"0".repeat(width - len));
                out.push_str(rest);
            } else {
                out.push_str(&"0".repeat(width - len));
                out.push_str(&body);
            }
        } else {
            out.push_str(&" ".repeat(width - len));
            out.push_str(&body);
        }
    }
    out
}

fn pad_prec(s: String, prec: Option<usize>) -> String {
    match prec {
        Some(p) if s.len() < p => format!("{}{}", "0".repeat(p - s.len()), s),
        _ => s,
    }
}

/// Format with printf style string.
#[macro_export]
macro_rules! wfmt {
    ($fmt:expr) => { $crate::strfn::sprintf($fmt, &[]) };
    ($fmt:expr, $($a:expr),+ $(,)?) => {
        $crate::strfn::sprintf($fmt, &[$($crate::strfn::Arg::from($a)),+])
    };
}

pub fn is_digit(c: char) -> bool {
    c.is_ascii_digit()
}

pub fn is_space(c: char) -> bool {
    c == ' ' || c == '\t'
}

/// Fast English-only toupper.
pub fn etoupperw(c: char) -> char {
    c.to_ascii_uppercase()
}

pub fn toupperw(c: char) -> char {
    let mut u = c.to_uppercase();
    match (u.next(), u.next()) {
        (Some(x), None) => x,
        _ => c,
    }
}

pub fn wcsupper(s: &str) -> String {
    s.chars().map(toupperw).collect()
}

pub fn wcslower(s: &str) -> String {
    s.chars()
        .map(|c| {
            let mut l = c.to_lowercase();
            match (l.next(), l.next()) {
                (Some(x), None) => x,
                _ => c,
            }
        })
        .collect()
}

/// Case insensitive compare, returns ordering like wcsicmp.
pub fn wcsicomp(a: &str, b: &str) -> std::cmp::Ordering {
    let a = wcsupper(a);
    let b = wcsupper(b);
    a.cmp(&b)
}

pub fn wcsicomp_eq(a: &str, b: &str) -> bool {
    wcsicomp(a, b) == std::cmp::Ordering::Equal
}

/// Compare first n characters case insensitively.
pub fn wcsnicomp_eq(a: &str, b: &str, n: usize) -> bool {
    let a: Vec<char> = a.chars().take(n).map(toupperw).collect();
    let b: Vec<char> = b.chars().take(n).map(toupperw).collect();
    a == b
}

/// Path comparison: case sensitive in Unix.
pub fn wcsicompc_eq(a: &str, b: &str) -> bool {
    if cfg!(unix) {
        a == b
    } else {
        wcsicomp_eq(a, b)
    }
}

pub fn wcsnicompc_eq(a: &[char], b: &[char], n: usize) -> bool {
    for i in 0..n {
        let x = a.get(i).copied().unwrap_or('\0');
        let y = b.get(i).copied().unwrap_or('\0');
        let eq = if cfg!(unix) { x == y } else { toupperw(x) == toupperw(y) };
        if !eq {
            return false;
        }
        if x == '\0' {
            return true;
        }
    }
    true
}

pub fn remove_lf(s: &mut String) {
    while s.ends_with('\r') || s.ends_with('\n') {
        s.pop();
    }
}

pub fn remove_eol(s: &mut String) {
    while s.ends_with('\r') || s.ends_with('\n') || s.ends_with(' ') || s.ends_with('\t') {
        s.pop();
    }
}

pub fn bin_to_hex(bin: &[u8]) -> String {
    bin.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn get_digits(mut n: u32) -> u32 {
    let mut d = 1;
    while n >= 10 {
        n /= 10;
        d += 1;
    }
    d
}

/// atoi for wide strings: parse leading digits, ignoring the rest.
pub fn atoiw(s: &str) -> i64 {
    let s = s.trim_start();
    let mut neg = false;
    let mut chars = s.chars().peekable();
    if let Some(&c) = chars.peek() {
        if c == '-' || c == '+' {
            neg = c == '-';
            chars.next();
        }
    }
    let mut n: i64 = 0;
    for c in chars {
        if let Some(d) = c.to_digit(10) {
            n = n.wrapping_mul(10).wrapping_add(d as i64);
        } else {
            break;
        }
    }
    if neg {
        -n
    } else {
        n
    }
}

pub fn truncate_at_zero(s: &mut String) {
    if let Some(p) = s.find('\0') {
        s.truncate(p);
    }
}

/// Replace ESC characters to prevent terminal escape sequence injection.
pub fn replace_esc(s: &str) -> String {
    s.replace('\x1b', "'\\033'")
}

/// Parse a string containing parameters separated with spaces, supporting
/// quote marks. Returns None if nothing left to parse.
pub fn get_cmd_param(cmd: &[char], pos: &mut usize) -> Option<String> {
    while *pos < cmd.len() && is_space(cmd[*pos]) {
        *pos += 1;
    }
    if *pos >= cmd.len() {
        return None;
    }
    let mut quote = false;
    let mut param = String::new();
    while *pos < cmd.len() && (quote || !is_space(cmd[*pos])) {
        if cmd[*pos] == '"' {
            if cmd.get(*pos + 1) == Some(&'"') {
                param.push('"');
                *pos += 1;
            } else {
                quote = !quote;
            }
        } else {
            param.push(cmd[*pos]);
        }
        *pos += 1;
    }
    Some(param)
}

pub fn low_ascii(s: &str) -> bool {
    s.chars().all(|c| (c as u32) <= 127)
}

#[cfg(test)]
mod tests {
    #[test]
    fn printf() {
        assert_eq!(wfmt!("%-5s|", "ab"), "ab   |");
        assert_eq!(wfmt!("%5s|", "ab"), "   ab|");
        assert_eq!(wfmt!("%8.8X", 0x1234abu32), "001234AB");
        assert_eq!(wfmt!("%02x%02x", 1u8, 255u8), "01ff");
        assert_eq!(wfmt!("%3d%%", 42), " 42%");
        assert_eq!(wfmt!("%.3s", "abcdef"), "abc");
        assert_eq!(wfmt!("%u-%02u", 2024u32, 3u32), "2024-03");
        assert_eq!(wfmt!("%09u", 5u32), "000000005");
        assert_eq!(wfmt!("%c%c", 'a', 'b'), "ab");
    }
}
