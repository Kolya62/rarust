// SPDX-License-Identifier: GPL-3.0-or-later

//! CRC-32 (IEEE 802.3, reflected polynomial 0xEDB88320) and the RAR 1.4
//! header checksum.

const POLY: u32 = 0xedb8_8320;

/// Tables for slicing-by-8: `T[0]` is the classic byte table, `T[k][b]` is
/// the CRC of byte `b` followed by `k` zero bytes.
const fn build() -> [[u32; 256]; 8] {
    let mut t = [[0u32; 256]; 8];
    let mut b = 0;
    while b < 256 {
        let mut r = b as u32;
        let mut i = 0;
        while i < 8 {
            r = if r & 1 != 0 { (r >> 1) ^ POLY } else { r >> 1 };
            i += 1;
        }
        t[0][b] = r;
        b += 1;
    }
    let mut k = 1;
    while k < 8 {
        let mut b = 0;
        while b < 256 {
            let p = t[k - 1][b];
            t[k][b] = (p >> 8) ^ t[0][(p & 0xff) as usize];
            b += 1;
        }
        k += 1;
    }
    t
}

static T: [[u32; 256]; 8] = build();

/// Byte-wise CRC-32 table (also used by RAR 1.5 and 2.0 encryption).
pub fn crc_table() -> &'static [u32; 256] {
    &T[0]
}

/// Updates the CRC register `crc` with `data`. No initial or final
/// inversion is applied: callers start from `0xffffffff` and invert the
/// result themselves when needed.
pub fn crc32(mut crc: u32, data: &[u8]) -> u32 {
    let mut chunks = data.chunks_exact(8);
    for c in &mut chunks {
        let lo = crc ^ u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
        let hi = u32::from_le_bytes([c[4], c[5], c[6], c[7]]);
        crc = T[7][(lo & 0xff) as usize]
            ^ T[6][((lo >> 8) & 0xff) as usize]
            ^ T[5][((lo >> 16) & 0xff) as usize]
            ^ T[4][(lo >> 24) as usize]
            ^ T[3][(hi & 0xff) as usize]
            ^ T[2][((hi >> 8) & 0xff) as usize]
            ^ T[1][((hi >> 16) & 0xff) as usize]
            ^ T[0][(hi >> 24) as usize];
    }
    for &b in chunks.remainder() {
        crc = (crc >> 8) ^ T[0][((crc ^ b as u32) & 0xff) as usize];
    }
    crc
}

/// RAR 1.4 checksum: add each byte, then rotate the 16-bit sum left by one.
pub fn checksum14(mut sum: u16, data: &[u8]) -> u16 {
    for &b in data {
        sum = sum.wrapping_add(b as u16).rotate_left(1);
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytewise(mut crc: u32, data: &[u8]) -> u32 {
        for &b in data {
            crc ^= b as u32;
            for _ in 0..8 {
                crc = if crc & 1 != 0 { (crc >> 1) ^ POLY } else { crc >> 1 };
            }
        }
        crc
    }

    #[test]
    fn vectors() {
        assert_eq!(crc32(!0, b"123456789") ^ !0, 0xcbf4_3926);
        assert_eq!(crc32(!0, b"testtesttest") ^ !0, 0x4460_8e84);
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 7 + 3) as u8).collect();
        for n in [0, 1, 7, 8, 9, 63, 1000] {
            assert_eq!(crc32(0x1234_5678, &data[..n]), bytewise(0x1234_5678, &data[..n]));
        }
    }
}
