// SPDX-License-Identifier: GPL-3.0-or-later

//! Unicode file names of RAR 2.x-4.x. The header stores an 8-bit name, a
//! zero byte and a compact encoding of the UTF-16 name that refers back
//! to the 8-bit name:
//!
//! ```text
//! high   u8   default high byte
//! then groups of a flag byte and up to four items, two flag bits each:
//!   0  low byte, high byte 0
//!   1  low byte, default high byte
//!   2  low byte, high byte
//!   3  run: n u8; if n & 0x80: correction u8 and (n & 0x7f) + 2
//!      characters made of (8-bit name byte + correction) and the default
//!      high byte; otherwise n + 2 characters copied from the 8-bit name
//! ```

pub fn decode(name: &[u8], enc: &[u8]) -> String {
    let mut units: Vec<u16> = Vec::with_capacity(name.len());
    let Some((&high, mut rest)) = enc.split_first() else { return String::new() };
    let high = (high as u16) << 8;
    let next = |rest: &mut &[u8]| -> Option<u8> {
        let (&b, r) = rest.split_first()?;
        *rest = r;
        Some(b)
    };
    'outer: while let Some(flags) = next(&mut rest) {
        for shift in [6, 4, 2, 0] {
            if rest.is_empty() {
                break 'outer;
            }
            match (flags >> shift) & 3 {
                0 => units.push(next(&mut rest).unwrap() as u16),
                1 => units.push(next(&mut rest).unwrap() as u16 | high),
                2 => {
                    if rest.len() < 2 {
                        continue;
                    }
                    let lo = next(&mut rest).unwrap() as u16;
                    let hi = next(&mut rest).unwrap() as u16;
                    units.push(lo | hi << 8);
                }
                _ => {
                    let n = next(&mut rest).unwrap();
                    if n & 0x80 != 0 {
                        let Some(corr) = next(&mut rest) else { continue };
                        for _ in 0..(n & 0x7f) as usize + 2 {
                            let Some(&b) = name.get(units.len()) else { break };
                            units.push(b.wrapping_add(corr) as u16 | high);
                        }
                    } else {
                        for _ in 0..n as usize + 2 {
                            let Some(&b) = name.get(units.len()) else { break };
                            units.push(b as u16);
                        }
                    }
                }
            }
        }
    }
    let mut s = String::from_utf16_lossy(&units);
    if let Some(z) = s.find('\0') {
        s.truncate(z);
    }
    s
}
