// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Mark of the Web propagation from archive to extracted files.
//!
//! Zone.Identifier stream can include the text like:
//!
//! ```text
//! [ZoneTransfer]
//! ZoneId=3
//! HostUrl=https://site/path/file.ext
//! ReferrerUrl=d:\path\archive.ext
//! ```
//!
//! Where ZoneId can be 0 (My Computer), 1 (Local intranet),
//! 2 (Trusted sites), 3 (Internet) or 4 (Restricted sites).

use crate::file::{File, FMF_READ};
use crate::matchfn::{cmp_name, MATCH_NAMES};
use crate::pathfn::get_ext_pos;
use crate::strfn::wcsicomp_eq;
use crate::strlist::StringList;

const MOTW_STREAM_MAX_SIZE: usize = 4096;
/// Must start from ':'.
pub const MOTW_STREAM_NAME: &str = ":Zone.Identifier";

#[derive(Clone, Debug)]
pub struct MarkOfTheWeb {
    /// Archive ":Zone.Identifier" NTFS stream data.
    zone_id_stream: Vec<u8>,
    /// -1 if missing.
    zone_id_value: i32,
    /// Copy all MOTW fields or ZoneId only.
    all_fields: bool,
}

impl Default for MarkOfTheWeb {
    fn default() -> Self {
        MarkOfTheWeb { zone_id_stream: Vec::new(), zone_id_value: -1, all_fields: false }
    }
}

fn find(s: &[u8], what: &[u8], from: usize) -> Option<usize> {
    if from > s.len() {
        return None;
    }
    s[from..].windows(what.len()).position(|w| w == what).map(|p| p + from)
}

impl MarkOfTheWeb {
    pub fn clear(&mut self) {
        self.zone_id_value = -1;
    }

    pub fn read_zone_id_stream(&mut self, file_name: &str, all_fields: bool) {
        self.all_fields = all_fields;
        self.zone_id_value = -1;
        self.zone_id_stream.clear();
        let mut src = File::new();
        if src.open(&format!("{}{}", file_name, MOTW_STREAM_NAME), FMF_READ) {
            let mut buf = vec![0u8; MOTW_STREAM_MAX_SIZE];
            let n = src.read(&mut buf);
            buf.truncate(n.max(0) as usize);
            self.zone_id_stream = buf;
            if n <= 0 {
                return;
            }
            let mut s = std::mem::take(&mut self.zone_id_stream);
            self.zone_id_value = self.parse_zone_id_stream(&mut s);
            self.zone_id_stream = s;
        }
    }

    /// `stream` contains the raw "Zone.Identifier" NTFS stream data on input
    /// and either raw or cleaned stream data on output.
    fn parse_zone_id_stream(&self, stream: &mut Vec<u8>) -> i32 {
        if !stream.starts_with(b"[ZoneTransfer]") {
            return -1; // Not a valid Mark of the Web. Prefer the archive MOTW, if any.
        }
        let zone_id = match find(stream, b"ZoneId=", 0) {
            Some(p) => p,
            None => return -1,
        };
        let at = |i: usize| stream.get(i).copied().unwrap_or(0);
        if !at(zone_id + 7).is_ascii_digit() {
            return -1;
        }
        let e = at(zone_id + 8);
        if e != 0 && e != b' ' && e != b'\t' && e != b'\r' && e != b'\n' {
            return -1;
        }
        let value = (at(zone_id + 7) - b'0') as i32;
        if value > 4 {
            return -1;
        }
        if find(stream, b"ZoneId=", zone_id + 8).is_some() {
            return -1;
        }
        if !self.all_fields {
            *stream = format!("[ZoneTransfer]\r\nZoneId={}\r\n", value).into_bytes();
        }
        value
    }

    pub fn create_zone_id_stream(&self, name: &str, motw_list: &StringList) {
        if self.zone_id_value == -1 {
            return;
        }
        let ext = match get_ext_pos(name) {
            Some(p) => &name[p + 1..],
            None => "",
        };
        let matched = motw_list.items().iter().any(|mask| {
            // Fast extension comparison for simple *.ext masks.
            let fast = mask.starts_with("*.") && !mask[2..].contains(['*', '?']);
            if fast {
                wcsicomp_eq(ext, &mask[2..])
            } else {
                cmp_name(mask, name, MATCH_NAMES)
            }
        });
        if !matched {
            return;
        }
        let mut f = File::new();
        if f.create(&format!("{}{}", name, MOTW_STREAM_NAME), crate::file::FMF_WRITE) {
            // Can fail on some network drives, so handle it silently.
            f.set_exceptions(false);
            if f.write(&self.zone_id_stream) {
                f.close();
            }
        }
    }

    pub fn is_name_conflicting(&self, stream_name: &str) -> bool {
        // Case insensitive comparison to catch names like ":zone.identifier".
        wcsicomp_eq(stream_name, MOTW_STREAM_NAME) && self.zone_id_value != -1
    }

    /// Return true and prepare the file stream to write if its ZoneId is
    /// stricter than archive ZoneId.
    pub fn is_file_stream_more_secure(&self, file_stream: &mut Vec<u8>) -> bool {
        self.parse_zone_id_stream(file_stream) > self.zone_id_value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        let m = MarkOfTheWeb::default();
        let mut s = b"[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=x\r\n".to_vec();
        assert_eq!(m.parse_zone_id_stream(&mut s), 3);
        assert_eq!(s, b"[ZoneTransfer]\r\nZoneId=3\r\n");
        let mut s = b"[ZoneTransfer]\r\nZoneId=31\r\n".to_vec();
        assert_eq!(m.parse_zone_id_stream(&mut s), -1);
        let mut s = b"[ZoneTransfer]\r\nZoneId=3\r\nZoneId=0".to_vec();
        assert_eq!(m.parse_zone_id_stream(&mut s), -1);
        let mut s = b"ZoneId=3".to_vec();
        assert_eq!(m.parse_zone_id_stream(&mut s), -1);
    }
}
