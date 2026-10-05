// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! CRC32 (slicing-by-16) and RAR 1.4 checksum.

const fn make_tables() -> [[u32; 256]; 16] {
    let mut t = [[0u32; 256]; 16];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut j = 0;
        while j < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xEDB8_8320 } else { c >> 1 };
            j += 1;
        }
        t[0][i] = c;
        i += 1;
    }
    let mut i = 0;
    while i < 256 {
        let mut c = t[0][i];
        let mut j = 1;
        while j < 16 {
            c = t[0][(c & 0xff) as usize] ^ (c >> 8);
            t[j][i] = c;
            j += 1;
        }
        i += 1;
    }
    t
}

static TABLES: [[u32; 256]; 16] = make_tables();

/// Classic CRC32 table, also used by legacy RAR encryption.
pub fn crc_table() -> &'static [u32; 256] {
    &TABLES[0]
}

/// Update CRC32 with data. Pass 0xffffffff as initial value and XOR result
/// with 0xffffffff to get the standard CRC32.
pub fn crc32(mut crc: u32, data: &[u8]) -> u32 {
    let t = &TABLES;
    #[allow(clippy::chunks_exact_to_as_chunks)]
    let mut chunks = data.chunks_exact(16);
    for c in &mut chunks {
        crc ^= u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
        let d1 = u32::from_le_bytes([c[4], c[5], c[6], c[7]]);
        let d2 = u32::from_le_bytes([c[8], c[9], c[10], c[11]]);
        let d3 = u32::from_le_bytes([c[12], c[13], c[14], c[15]]);
        crc = t[15][(crc & 0xff) as usize]
            ^ t[14][((crc >> 8) & 0xff) as usize]
            ^ t[13][((crc >> 16) & 0xff) as usize]
            ^ t[12][(crc >> 24) as usize]
            ^ t[11][(d1 & 0xff) as usize]
            ^ t[10][((d1 >> 8) & 0xff) as usize]
            ^ t[9][((d1 >> 16) & 0xff) as usize]
            ^ t[8][(d1 >> 24) as usize]
            ^ t[7][(d2 & 0xff) as usize]
            ^ t[6][((d2 >> 8) & 0xff) as usize]
            ^ t[5][((d2 >> 16) & 0xff) as usize]
            ^ t[4][(d2 >> 24) as usize]
            ^ t[3][(d3 & 0xff) as usize]
            ^ t[2][((d3 >> 8) & 0xff) as usize]
            ^ t[1][((d3 >> 16) & 0xff) as usize]
            ^ t[0][(d3 >> 24) as usize];
    }
    for &b in chunks.remainder() {
        crc = t[0][((crc ^ b as u32) & 0xff) as usize] ^ (crc >> 8);
    }
    crc
}

/// RAR 1.4 archive checksum.
pub fn checksum14(mut crc: u16, data: &[u8]) -> u16 {
    for &b in data {
        crc = crc.wrapping_add(b as u16);
        crc = crc.rotate_left(1);
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn vectors() {
        assert_eq!(crc32(0xffffffff, b"testtesttest") ^ 0xffffffff, 0x44608e84);
        assert_eq!(crc32(0, b"te\x80st"), 0xB2E5C5AE);
        let b: Vec<u8> = (0..14u8).map(|i| 0x7f + i).collect();
        assert_eq!(crc32(0xffffffff, &b) ^ 0xffffffff, 0x1DFA75DA);
        let mut b: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
        let mut r = crc32(0xffffffff, &b);
        for i in 300..1024u32 {
            b[0] = i as u8;
            r = crc32(r, &b[..1]);
        }
        assert_eq!(r ^ 0xffffffff, 0xB70B4C26);
    }
}
