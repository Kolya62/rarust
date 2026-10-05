// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Decoder of RAR 2.x/3.x Unicode file names.

pub fn decode(name: &[u8], enc: &[u8]) -> String {
    let mut out: Vec<u32> = Vec::new();
    let mut enc_pos = 0;
    let mut dec_pos = 0;
    let mut flags: u32 = 0;
    let mut flag_bits = 0;
    let high_byte = if enc_pos < enc.len() {
        enc_pos += 1;
        enc[0] as u32
    } else {
        0
    };
    let set = |out: &mut Vec<u32>, pos: usize, v: u32| {
        if out.len() <= pos {
            out.resize(pos + 1, 0);
        }
        out[pos] = v;
    };
    while enc_pos < enc.len() {
        if flag_bits == 0 {
            flags = enc[enc_pos] as u32;
            enc_pos += 1;
            flag_bits = 8;
        }
        match (flags >> 6) & 3 {
            0 => {
                if enc_pos < enc.len() {
                    set(&mut out, dec_pos, enc[enc_pos] as u32);
                    dec_pos += 1;
                    enc_pos += 1;
                }
            }
            1 => {
                if enc_pos < enc.len() {
                    set(&mut out, dec_pos, enc[enc_pos] as u32 + (high_byte << 8));
                    dec_pos += 1;
                    enc_pos += 1;
                }
            }
            2 => {
                if enc_pos + 1 < enc.len() {
                    set(&mut out, dec_pos, enc[enc_pos] as u32 + ((enc[enc_pos + 1] as u32) << 8));
                    dec_pos += 1;
                    enc_pos += 2;
                }
            }
            _ => {
                if enc_pos < enc.len() {
                    let mut length = enc[enc_pos] as u32;
                    enc_pos += 1;
                    if length & 0x80 != 0 {
                        if enc_pos < enc.len() {
                            let correction = enc[enc_pos] as u32;
                            enc_pos += 1;
                            length = (length & 0x7f) + 2;
                            while length > 0 && dec_pos < name.len() {
                                set(&mut out, dec_pos, ((name[dec_pos] as u32 + correction) & 0xff) + (high_byte << 8));
                                length -= 1;
                                dec_pos += 1;
                            }
                        }
                    } else {
                        length += 2;
                        while length > 0 && dec_pos < name.len() {
                            set(&mut out, dec_pos, name[dec_pos] as u32);
                            length -= 1;
                            dec_pos += 1;
                        }
                    }
                }
            }
        }
        flags = (flags << 2) & 0xff;
        flag_bits -= 2;
    }
    // Values are UTF-16 code units.
    let units: Vec<u16> = out.iter().map(|&u| u as u16).collect();
    let mut s = String::from_utf16_lossy(&units);
    if let Some(p) = s.find('\0') {
        s.truncate(p);
    }
    s
}
