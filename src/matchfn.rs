// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Wildcard matching of file names.

use crate::pathfn::{at, chars, get_name_pos_c};
use crate::strfn::toupperw;

pub const MATCH_NAMES: u32 = 0;
pub const MATCH_SUBPATHONLY: u32 = 1;
pub const MATCH_EXACT: u32 = 2;
pub const MATCH_ALLWILD: u32 = 3;
pub const MATCH_EXACTPATH: u32 = 4;
pub const MATCH_SUBPATH: u32 = 5;
pub const MATCH_WILDSUBPATH: u32 = 6;
pub const MATCH_MODEMASK: u32 = 0x0000ffff;
pub const MATCH_FORCECASESENSITIVE: u32 = 0x80000000;

fn upc(c: char, force: bool) -> char {
    if force || cfg!(unix) {
        c
    } else {
        toupperw(c)
    }
}

fn mwcsicompc(a: &[char], b: &[char], force: bool) -> bool {
    if force || cfg!(unix) {
        a == b
    } else {
        a.len() == b.len() && a.iter().zip(b).all(|(x, y)| toupperw(*x) == toupperw(*y))
    }
}

fn mwcsnicompc(a: &[char], b: &[char], n: usize, force: bool) -> bool {
    for i in 0..n {
        let x = at(a, i);
        let y = at(b, i);
        let eq = if force || cfg!(unix) { x == y } else { toupperw(x) == toupperw(y) };
        if !eq {
            return false;
        }
        if x == '\0' {
            return true;
        }
    }
    true
}

fn is_wildcard_n(s: &[char], n: usize) -> bool {
    s.iter().take(n).any(|&c| c == '*' || c == '?')
}

pub fn cmp_name(wildcard: &str, name: &str, cmp_mode: u32) -> bool {
    let w = chars(wildcard);
    let n = chars(name);
    cmp_name_c(&w, &n, cmp_mode)
}

pub fn cmp_name_c(w: &[char], n: &[char], cmp_mode: u32) -> bool {
    let force = cmp_mode & MATCH_FORCECASESENSITIVE != 0;
    let mode = cmp_mode & MATCH_MODEMASK;
    let p1 = get_name_pos_c(w);
    let p2 = get_name_pos_c(n);
    if mode != MATCH_NAMES {
        let wl = w.len();
        if mode != MATCH_EXACT && mode != MATCH_EXACTPATH && mode != MATCH_ALLWILD && mwcsnicompc(w, n, wl, force) {
            let next = at(n, wl);
            if next == '\\' || next == '/' || next == '\0' {
                return true;
            }
        }
        if mode == MATCH_SUBPATHONLY {
            return false;
        }
        if (mode == MATCH_EXACT || mode == MATCH_EXACTPATH) && (p1 != p2 || !mwcsnicompc(w, n, p1, force)) {
            return false;
        }
        if mode == MATCH_ALLWILD {
            return do_match(w, n, force);
        }
        if mode == MATCH_SUBPATH || mode == MATCH_WILDSUBPATH {
            if is_wildcard_n(w, p1) {
                return do_match(w, n, force);
            } else if mode == MATCH_SUBPATH || w.iter().any(|&c| c == '*' || c == '?') {
                if p1 > 0 && !mwcsnicompc(w, n, p1, force) {
                    return false;
                }
            } else if p1 != p2 || !mwcsnicompc(w, n, p1, force) {
                return false;
            }
        }
    }
    if mode == MATCH_EXACT {
        return mwcsicompc(&w[p1..], &n[p2..], force);
    }
    do_match(&w[p1..], &n[p2..], force)
}

fn do_match(pattern: &[char], string: &[char], force: bool) -> bool {
    let mut pi = 0;
    let mut si = 0;
    loop {
        let sc = upc(at(string, si), force);
        let pc = upc(at(pattern, pi), force);
        pi += 1;
        match pc {
            '\0' => return sc == '\0',
            '?' => {
                if sc == '\0' {
                    return false;
                }
            }
            '*' => {
                if at(pattern, pi) == '\0' {
                    return true;
                }
                if at(pattern, pi) == '.' {
                    if at(pattern, pi + 1) == '*' && at(pattern, pi + 2) == '\0' {
                        return true;
                    }
                    let dot = string[si.min(string.len())..].iter().position(|&c| c == '.').map(|p| p + si);
                    if at(pattern, pi + 1) == '\0' {
                        return dot.is_none() || at(string, dot.unwrap() + 1) == '\0';
                    }
                    if let Some(d) = dot {
                        si = d;
                        let pat_rest = &pattern[pi.min(pattern.len())..];
                        if !pat_rest.iter().any(|&c| c == '*' || c == '?')
                            && !string[(si + 1).min(string.len())..].contains(&'.')
                        {
                            return mwcsicompc(&pattern[(pi + 1).min(pattern.len())..], &string[(si + 1).min(string.len())..], force);
                        }
                    }
                }
                while si < string.len() {
                    if do_match(&pattern[pi.min(pattern.len())..], &string[si..], force) {
                        return true;
                    }
                    si += 1;
                }
                return false;
            }
            _ => {
                if pc != sc {
                    if pc == '.' && (sc == '\0' || sc == '\\' || sc == '.') {
                        return do_match(&pattern[pi.min(pattern.len())..], &string[si.min(string.len())..], force);
                    }
                    return false;
                }
            }
        }
        si += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wild() {
        assert!(cmp_name("*", "abc/def", MATCH_WILDSUBPATH));
        assert!(cmp_name("*.txt", "a/b.txt", MATCH_WILDSUBPATH));
        assert!(!cmp_name("*.txt", "a/b.rs", MATCH_WILDSUBPATH));
        assert!(cmp_name("src", "src/lib.rs", MATCH_WILDSUBPATH));
        assert!(cmp_name("*.*", "noext", MATCH_NAMES));
        assert!(cmp_name("a?c", "abc", MATCH_NAMES));
        assert!(cmp_name("name.", "name", MATCH_NAMES));
    }
}
