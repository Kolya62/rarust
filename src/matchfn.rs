// SPDX-License-Identifier: GPL-3.0-or-later

//! Matching of file names against masks given on the command line.
//!
//! `*` matches any sequence and `?` any single character, with the
//! traditional DOS/Windows rules for dots: "*.*" matches names without an
//! extension, "name." matches "name", and "*." matches names without a
//! dot. Comparison ignores case except on Unix.
//!
//! The mode says how the path part of a mask is used:
//!
//! - `MATCH_NAMES`: only name parts are compared
//! - `MATCH_SUBPATHONLY`: the mask is a path prefix of the name
//! - `MATCH_EXACT`, `MATCH_EXACTPATH`: paths are equal; names are equal
//!   (`EXACT`) or match (`EXACTPATH`)
//! - `MATCH_ALLWILD`: whole strings match
//! - `MATCH_SUBPATH`: like `NAMES` below the mask's path
//! - `MATCH_WILDSUBPATH`: like `SUBPATH` for masks with wildcards, else
//!   paths are equal
//!
//! Except for `SUBPATHONLY`, `EXACT`, `EXACTPATH` and `ALLWILD`, a mask
//! also matches everything inside a directory with the mask's name.

use crate::pathfn::get_name_pos_c;
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

#[derive(Clone, Copy)]
struct Case {
    sensitive: bool,
}

impl Case {
    fn fold(self, c: char) -> char {
        if self.sensitive {
            c
        } else {
            toupperw(c)
        }
    }

    fn eq(self, a: char, b: char) -> bool {
        self.fold(a) == self.fold(b)
    }

    fn eq_str(self, a: &[char], b: &[char]) -> bool {
        a.len() == b.len() && a.iter().zip(b).all(|(&x, &y)| self.eq(x, y))
    }

    /// `name` starts with `prefix`.
    fn starts_with(self, name: &[char], prefix: &[char]) -> bool {
        name.len() >= prefix.len() && self.eq_str(&name[..prefix.len()], prefix)
    }
}

fn has_wildcards(s: &[char]) -> bool {
    s.iter().any(|&c| c == '*' || c == '?')
}

pub fn cmp_name(mask: &str, name: &str, mode: u32) -> bool {
    let m: Vec<char> = mask.chars().collect();
    let n: Vec<char> = name.chars().collect();
    cmp_name_c(&m, &n, mode)
}

pub fn cmp_name_c(mask: &[char], name: &[char], mode: u32) -> bool {
    let case = Case { sensitive: mode & MATCH_FORCECASESENSITIVE != 0 || cfg!(unix) };
    let mode = mode & MATCH_MODEMASK;
    let mpos = get_name_pos_c(mask);
    let npos = get_name_pos_c(name);
    let same_path = || mpos == npos && case.eq_str(&mask[..mpos], &name[..mpos]);

    if mode != MATCH_NAMES {
        // The mask names a directory containing `name`, or `name` itself.
        if !matches!(mode, MATCH_EXACT | MATCH_EXACTPATH | MATCH_ALLWILD)
            && case.starts_with(name, mask)
            && matches!(name.get(mask.len()), None | Some('\\') | Some('/'))
        {
            return true;
        }
        match mode {
            MATCH_SUBPATHONLY => return false,
            MATCH_EXACT | MATCH_EXACTPATH if !same_path() => return false,
            MATCH_ALLWILD => return wild(mask, name, case),
            MATCH_SUBPATH | MATCH_WILDSUBPATH => {
                if has_wildcards(&mask[..mpos]) {
                    return wild(mask, name, case);
                }
                if mode == MATCH_SUBPATH || has_wildcards(mask) {
                    // The mask's path must be a prefix of the name's path.
                    if mpos > 0 && !case.starts_with(name, &mask[..mpos]) {
                        return false;
                    }
                } else if !same_path() {
                    return false;
                }
            }
            _ => {}
        }
    }
    if mode == MATCH_EXACT {
        return case.eq_str(&mask[mpos..], &name[npos..]);
    }
    wild(&mask[mpos..], &name[npos..], case)
}

/// Wildcard match of a whole string.
fn wild(p: &[char], s: &[char], case: Case) -> bool {
    let Some((&pc, rest)) = p.split_first() else { return s.is_empty() };
    match pc {
        '?' => !s.is_empty() && wild(rest, &s[1..], case),
        '*' => star(rest, s, case),
        _ => match s.first() {
            Some(&sc) if case.eq(pc, sc) => wild(rest, &s[1..], case),
            // A dot in the mask may stand for a missing extension.
            None | Some('\\') | Some('.') if pc == '.' => wild(rest, s, case),
            _ => false,
        },
    }
}

/// Match of `*` followed by `rest` against `s`.
fn star(rest: &[char], s: &[char], case: Case) -> bool {
    if rest.is_empty() {
        return true;
    }
    let mut from = 0;
    if rest[0] == '.' {
        if rest == ['.', '*'] {
            return true;
        }
        let dot = s.iter().position(|&c| c == '.');
        if rest.len() == 1 {
            // "*." : no extension (or an empty one).
            return dot.is_none_or(|d| d + 1 == s.len());
        }
        if let Some(d) = dot {
            from = d;
            // Fixed extension and a single dot left: compare directly.
            if !has_wildcards(rest) && !s[d + 1..].contains(&'.') {
                return case.eq_str(&rest[1..], &s[d + 1..]);
            }
        }
    }
    // The star is not tried against an empty remainder.
    (from..s.len()).any(|i| wild(rest, &s[i..], case))
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
