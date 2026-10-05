// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Character set conversions. "Char" strings use the system ANSI code page
//! in Windows. Elsewhere they are treated as UTF-8, which is the typical
//! Unix locale. Bytes which cannot be decoded are mapped to the
//! 0xE080-0xE0FF private use area and restored when converting back,
//! for lossless round trip of Unix file names.

const MAP_AREA_START: u32 = 0xE000;
const MAPPED_STRING_MARK: char = '\u{FFFE}';

fn cut_zero(src: &[u8]) -> &[u8] {
    match src.iter().position(|&b| b == 0) {
        Some(p) => &src[..p],
        None => src,
    }
}

/// Decode UTF-8 bytes. Stops at first zero or invalid sequence.
pub fn utf_to_wide(src: &[u8]) -> String {
    let src = cut_zero(src);
    let mut out = String::new();
    let mut i = 0;
    let at = |i: usize| src.get(i).copied().unwrap_or(0) as u32;
    while i < src.len() {
        let c = src[i] as u32;
        i += 1;
        let d;
        if c < 0x80 {
            d = c;
        } else if (c >> 5) == 6 {
            if (at(i) & 0xc0) != 0x80 {
                break;
            }
            d = ((c & 0x1f) << 6) | (at(i) & 0x3f);
            i += 1;
        } else if (c >> 4) == 14 {
            if (at(i) & 0xc0) != 0x80 || (at(i + 1) & 0xc0) != 0x80 {
                break;
            }
            d = ((c & 0xf) << 12) | ((at(i) & 0x3f) << 6) | (at(i + 1) & 0x3f);
            i += 2;
        } else if (c >> 3) == 30 {
            if (at(i) & 0xc0) != 0x80 || (at(i + 1) & 0xc0) != 0x80 || (at(i + 2) & 0xc0) != 0x80 {
                break;
            }
            d = ((c & 7) << 18) | ((at(i) & 0x3f) << 12) | ((at(i + 1) & 0x3f) << 6) | (at(i + 2) & 0x3f);
            i += 3;
        } else {
            break;
        }
        if d > 0x10ffff {
            continue;
        }
        out.push(char::from_u32(d).unwrap_or('\u{FFFD}'));
    }
    out
}

pub fn wide_to_utf(s: &str) -> Vec<u8> {
    let s = match s.find('\0') {
        Some(p) => &s[..p],
        None => s,
    };
    s.as_bytes().to_vec()
}

/// Convert locale (UTF-8) encoded bytes to string, mapping undecodable
/// high bytes to private use area.
pub fn char_to_wide(src: &[u8]) -> String {
    #[cfg(windows)]
    return crate::win32::mb_to_wide(crate::win32::CP_ACP, cut_zero(src));
    #[cfg(not(windows))]
    utf8_char_to_wide(src)
}

#[cfg_attr(windows, allow(dead_code))]
fn utf8_char_to_wide(src: &[u8]) -> String {
    let src = cut_zero(src);
    if let Ok(s) = std::str::from_utf8(src) {
        return s.to_string();
    }
    let mut out = String::new();
    let mut mark_added = false;
    let mut i = 0;
    while i < src.len() {
        let rest = &src[i..];
        let valid = match std::str::from_utf8(rest) {
            Ok(s) => s.len(),
            Err(e) => e.valid_up_to(),
        };
        if valid > 0 {
            out.push_str(std::str::from_utf8(&rest[..valid]).unwrap());
            i += valid;
            continue;
        }
        let b = src[i];
        if b >= 0x80 {
            if !mark_added {
                out.push(MAPPED_STRING_MARK);
                mark_added = true;
            }
            out.push(char::from_u32(b as u32 + MAP_AREA_START).unwrap());
            i += 1;
        } else {
            break;
        }
    }
    out
}

/// Convert string to locale (UTF-8) bytes, restoring mapped characters.
pub fn wide_to_char(s: &str) -> Vec<u8> {
    #[cfg(windows)]
    return crate::win32::wide_to_mb(crate::win32::CP_ACP, s.split('\0').next().unwrap_or(""));
    #[cfg(not(windows))]
    utf8_wide_to_char(s)
}

#[cfg_attr(windows, allow(dead_code))]
fn utf8_wide_to_char(s: &str) -> Vec<u8> {
    let s = match s.find('\0') {
        Some(p) => &s[..p],
        None => s,
    };
    if !s.contains(MAPPED_STRING_MARK) {
        return s.as_bytes().to_vec();
    }
    let mut out = Vec::new();
    for c in s.chars() {
        if c == MAPPED_STRING_MARK {
            continue;
        }
        let u = c as u32;
        if (MAP_AREA_START + 0x80..MAP_AREA_START + 0x100).contains(&u) {
            out.push((u - MAP_AREA_START) as u8);
        } else {
            let mut b = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut b).as_bytes());
        }
    }
    out
}

/// Convert OEM encoded archive names and comments. Same as `char_to_wide`
/// outside of Windows.
pub fn oem_to_wide(src: &[u8]) -> String {
    // Convert OEM to ANSI first like OemToChar, so characters missing in
    // ANSI code page are replaced in the same way as in other Windows tools.
    #[cfg(windows)]
    {
        use crate::win32::*;
        let ansi = wide_to_mb(CP_ACP, &mb_to_wide(CP_OEMCP, cut_zero(src)));
        mb_to_wide(CP_ACP, &ansi)
    }
    #[cfg(not(windows))]
    char_to_wide(src)
}

/// Convert string to OEM encoding. Same as `wide_to_char` outside of Windows.
pub fn wide_to_oem(s: &str) -> Vec<u8> {
    #[cfg(windows)]
    return crate::win32::wide_to_mb(crate::win32::CP_OEMCP, s.split('\0').next().unwrap_or(""));
    #[cfg(not(windows))]
    wide_to_char(s)
}

/// Convert UTF-16LE raw bytes to string, stopping at zero character.
pub fn raw_to_wide(src: &[u8]) -> String {
    let mut units = Vec::new();
    let mut i = 0;
    while i + 1 < src.len() {
        let c = src[i] as u16 | ((src[i + 1] as u16) << 8);
        if c == 0 {
            break;
        }
        units.push(c);
        i += 2;
    }
    String::from_utf16_lossy(&units)
}

pub fn wide_to_raw(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

/// Convert string to path in the file system.
#[cfg(unix)]
pub fn to_path(s: &str) -> std::path::PathBuf {
    use std::os::unix::ffi::OsStringExt;
    std::path::PathBuf::from(std::ffi::OsString::from_vec(wide_to_char(s)))
}

#[cfg(not(unix))]
pub fn to_path(s: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(s)
}

/// Convert OS string to our string representation.
#[cfg(unix)]
pub fn from_os(s: &std::ffi::OsStr) -> String {
    use std::os::unix::ffi::OsStrExt;
    char_to_wide(s.as_bytes())
}

#[cfg(not(unix))]
pub fn from_os(s: &std::ffi::OsStr) -> String {
    s.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mapping() {
        let raw = b"ab\xff\xe9cd";
        let w = char_to_wide(raw);
        assert_eq!(wide_to_char(&w), raw.to_vec());
        assert_eq!(utf_to_wide("тест".as_bytes()), "тест");
    }
}
