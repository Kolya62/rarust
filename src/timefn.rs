// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! RAR time representation: nanoseconds since 01.01.1601.

use crate::tz;

const TICKS_PER_SECOND: u64 = 1_000_000_000;
const USHIFT: u64 = 11_644_473_600_000_000_000; // ns between 1601 and 1970.
pub const REMINDER_PRECISION: u32 = 1_000_000_000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct RarTime {
    itime: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RarLocalTime {
    pub year: u32,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
    pub reminder: u32,
    pub wday: u32,
    pub yday: u32,
}

impl RarTime {
    pub fn reset(&mut self) {
        self.itime = 0;
    }
    pub fn is_set(&self) -> bool {
        self.itime != 0
    }
    pub fn get_win(&self) -> u64 {
        self.itime / (TICKS_PER_SECOND / 10_000_000)
    }
    pub fn set_win(&mut self, t: u64) {
        self.itime = t.wrapping_mul(TICKS_PER_SECOND / 10_000_000);
    }
    pub fn get_unix(&self) -> i64 {
        (self.get_unix_ns() / 1_000_000_000) as i64
    }
    pub fn set_unix(&mut self, ut: i64) {
        self.set_unix_ns((ut as u64).wrapping_mul(1_000_000_000));
    }
    pub fn get_unix_ns(&self) -> u64 {
        self.itime.wrapping_mul(1_000_000_000 / TICKS_PER_SECOND).wrapping_sub(USHIFT)
    }
    pub fn set_unix_ns(&mut self, ns: u64) {
        self.itime = ns.wrapping_add(USHIFT) / (1_000_000_000 / TICKS_PER_SECOND);
    }
    pub fn adjust(&mut self, ns: i64) {
        self.itime = self.itime.wrapping_add(ns as u64);
    }

    pub fn get_local(&self) -> RarLocalTime {
        let ut = self.get_unix_ns() as i64;
        let ut = ut.div_euclid(1_000_000_000);
        let lt = ut + tz::local_offset(ut);
        let days = lt.div_euclid(86400);
        let secs = lt.rem_euclid(86400);
        let (y, m, d) = tz::civil_from_days(days);
        let jan1 = tz::timegm(y, 1, 1, 0, 0, 0).div_euclid(86400);
        RarLocalTime {
            year: y as u32,
            month: m,
            day: d,
            hour: (secs / 3600) as u32,
            minute: (secs / 60 % 60) as u32,
            second: (secs % 60) as u32,
            reminder: (self.itime % TICKS_PER_SECOND) as u32,
            wday: (days + 4).rem_euclid(7) as u32,
            yday: (days - jan1) as u32,
        }
    }

    pub fn set_local(&mut self, lt: &RarLocalTime) {
        let t = tz::mktime(
            lt.year as i64,
            lt.month,
            lt.day,
            lt.hour as i64,
            lt.minute as i64,
            lt.second as i64,
        );
        self.set_unix(t);
        self.itime = self.itime.wrapping_add(lt.reminder as u64);
    }

    pub fn get_dos(&self) -> u32 {
        let lt = self.get_local();
        (lt.second / 2) | (lt.minute << 5) | (lt.hour << 11) | (lt.day << 16) | (lt.month << 21) | ((lt.year.wrapping_sub(1980)) << 25)
    }

    pub fn set_dos(&mut self, dos: u32) {
        let lt = RarLocalTime {
            second: (dos & 0x1f) * 2,
            minute: (dos >> 5) & 0x3f,
            hour: (dos >> 11) & 0x1f,
            day: (dos >> 16) & 0x1f,
            month: (dos >> 21) & 0x0f,
            year: (dos >> 25) + 1980,
            ..Default::default()
        };
        self.set_local(&lt);
    }

    pub fn get_text(&self, full_ms: bool) -> String {
        if self.is_set() {
            let lt = self.get_local();
            if full_ms {
                crate::wfmt!(
                    "%u-%02u-%02u %02u:%02u:%02u,%09u",
                    lt.year,
                    lt.month,
                    lt.day,
                    lt.hour,
                    lt.minute,
                    lt.second,
                    lt.reminder
                )
            } else {
                crate::wfmt!("%u-%02u-%02u %02u:%02u", lt.year, lt.month, lt.day, lt.hour, lt.minute)
            }
        } else {
            "????-??-?? ??:??".to_string()
        }
    }

    pub fn set_iso_text(&mut self, text: &str) {
        let mut field = [0i64; 6];
        let mut digits = 0usize;
        for c in text.chars() {
            if c.is_ascii_digit() {
                let pos = if digits < 4 { 0 } else { (digits - 4) / 2 + 1 };
                if pos < 6 {
                    field[pos] = field[pos] * 10 + (c as i64 - '0' as i64);
                }
                digits += 1;
            }
        }
        let lt = RarLocalTime {
            second: field[5] as u32,
            minute: field[4] as u32,
            hour: field[3] as u32,
            day: if field[2] == 0 { 1 } else { field[2] as u32 },
            month: if field[1] == 0 { 1 } else { field[1] as u32 },
            year: field[0] as u32,
            ..Default::default()
        };
        self.set_local(&lt);
    }

    pub fn set_age_text(&mut self, text: &str) {
        let mut seconds: u64 = 0;
        let mut value: u64 = 0;
        for c in text.chars() {
            if let Some(d) = c.to_digit(10) {
                value = value * 10 + d as u64;
            } else {
                match c.to_ascii_uppercase() {
                    'D' => seconds += value * 24 * 3600,
                    'H' => seconds += value * 3600,
                    'M' => seconds += value * 60,
                    'S' => seconds += value,
                    _ => {}
                }
                value = 0;
            }
        }
        self.set_current_time();
        self.itime = self.itime.wrapping_sub(seconds * TICKS_PER_SECOND);
    }

    pub fn set_current_time(&mut self) {
        let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        self.set_unix(d.as_secs() as i64);
    }

    pub fn from_system_time(t: std::time::SystemTime) -> RarTime {
        let mut r = RarTime::default();
        match t.duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => r.set_unix_ns(d.as_secs().wrapping_mul(1_000_000_000).wrapping_add(d.subsec_nanos() as u64)),
            Err(e) => {
                let d = e.duration();
                r.set_unix_ns((d.as_nanos() as u64).wrapping_neg());
            }
        }
        r
    }

    pub fn to_system_time(&self) -> std::time::SystemTime {
        let ns = self.get_unix_ns() as i64;
        if ns >= 0 {
            std::time::UNIX_EPOCH + std::time::Duration::from_nanos(ns as u64)
        } else {
            std::time::UNIX_EPOCH - std::time::Duration::from_nanos(ns.unsigned_abs())
        }
    }
}

pub fn is_leap_year(y: u32) -> bool {
    tz::is_leap(y as i64)
}
