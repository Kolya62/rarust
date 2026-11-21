// SPDX-License-Identifier: GPL-3.0-or-later

//! Time stamps: nanoseconds since 1601-01-01 UTC, the epoch of Windows
//! FILETIME, which keeps all RAR time formats (DOS, FILETIME, Unix
//! seconds and nanoseconds) exact.

use crate::tz;

const NS: u64 = 1_000_000_000;
/// Nanoseconds from 1601-01-01 to 1970-01-01.
const UNIX_EPOCH_NS: u64 = 11_644_473_600 * NS;
/// Units of `RarLocalTime::reminder` per second.
pub const REMINDER_PRECISION: u32 = NS as u32;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct RarTime {
    ns: u64,
}

/// Broken down local time. `reminder` is the fraction of the second in
/// nanoseconds.
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
        self.ns = 0;
    }

    /// Zero means "not set".
    pub fn is_set(&self) -> bool {
        self.ns != 0
    }

    /// Windows FILETIME: 100 ns units.
    pub fn get_win(&self) -> u64 {
        self.ns / 100
    }
    pub fn set_win(&mut self, t: u64) {
        self.ns = t.wrapping_mul(100);
    }

    pub fn get_unix_ns(&self) -> u64 {
        self.ns.wrapping_sub(UNIX_EPOCH_NS)
    }
    pub fn set_unix_ns(&mut self, ns: u64) {
        self.ns = ns.wrapping_add(UNIX_EPOCH_NS);
    }
    pub fn get_unix(&self) -> i64 {
        (self.get_unix_ns() / NS) as i64
    }
    pub fn set_unix(&mut self, secs: i64) {
        self.set_unix_ns((secs as u64).wrapping_mul(NS));
    }

    /// Adds `ns` nanoseconds.
    pub fn adjust(&mut self, ns: i64) {
        self.ns = self.ns.wrapping_add(ns as u64);
    }

    pub fn get_local(&self) -> RarLocalTime {
        let secs = (self.get_unix_ns() as i64).div_euclid(NS as i64);
        let local = secs + tz::local_offset(secs);
        let days = local.div_euclid(86400);
        let in_day = local.rem_euclid(86400) as u32;
        let (year, month, day) = tz::civil_from_days(days);
        let year_start = tz::timegm(year, 1, 1, 0, 0, 0).div_euclid(86400);
        RarLocalTime {
            year: year as u32,
            month,
            day,
            hour: in_day / 3600,
            minute: in_day / 60 % 60,
            second: in_day % 60,
            reminder: (self.ns % NS) as u32,
            // 1970-01-01 was a Thursday.
            wday: (days + 4).rem_euclid(7) as u32,
            yday: (days - year_start) as u32,
        }
    }

    pub fn set_local(&mut self, lt: &RarLocalTime) {
        let secs = tz::mktime(lt.year as i64, lt.month, lt.day, lt.hour as i64, lt.minute as i64, lt.second as i64);
        self.set_unix(secs);
        self.ns = self.ns.wrapping_add(lt.reminder as u64);
    }

    /// MS-DOS date and time in local time, 2 second precision:
    /// bits 0-4 seconds / 2, 5-10 minutes, 11-15 hours, 16-20 day,
    /// 21-24 month, 25-31 years since 1980.
    pub fn get_dos(&self) -> u32 {
        let t = self.get_local();
        t.second / 2 | t.minute << 5 | t.hour << 11 | t.day << 16 | t.month << 21 | t.year.wrapping_sub(1980) << 25
    }

    pub fn set_dos(&mut self, dos: u32) {
        let field = |shift: u32, bits: u32| (dos >> shift) & ((1 << bits) - 1);
        self.set_local(&RarLocalTime {
            second: field(0, 5) * 2,
            minute: field(5, 6),
            hour: field(11, 5),
            day: field(16, 5),
            month: field(21, 4),
            year: field(25, 7) + 1980,
            ..Default::default()
        });
    }

    /// "YYYY-MM-DD HH:MM", or with seconds and nanoseconds.
    pub fn get_text(&self, full: bool) -> String {
        if !self.is_set() {
            return "????-??-?? ??:??".to_string();
        }
        let t = self.get_local();
        let base = format!("{}-{:02}-{:02} {:02}:{:02}", t.year, t.month, t.day, t.hour, t.minute);
        if full {
            format!("{base}:{:02},{:09}", t.second, t.reminder)
        } else {
            base
        }
    }

    /// Parses "YYYY[MM[DD[HH[MM[SS]]]]]" in local time; separators
    /// between digits are ignored and missing month or day mean 1.
    pub fn set_iso_text(&mut self, text: &str) {
        let digits: Vec<i64> = text.chars().filter_map(|c| c.to_digit(10)).map(i64::from).collect();
        // Field lengths: year 4, then 2 each.
        let mut f = [0i64; 6];
        for (n, d) in digits.iter().enumerate() {
            let i = if n < 4 { 0 } else { (n - 4) / 2 + 1 };
            if i < 6 {
                f[i] = f[i] * 10 + d;
            }
        }
        let one_if_zero = |v: i64| if v == 0 { 1 } else { v as u32 };
        self.set_local(&RarLocalTime {
            year: f[0] as u32,
            month: one_if_zero(f[1]),
            day: one_if_zero(f[2]),
            hour: f[3] as u32,
            minute: f[4] as u32,
            second: f[5] as u32,
            ..Default::default()
        });
    }

    /// Current time minus an age like "1d2h30m", "45s".
    pub fn set_age_text(&mut self, text: &str) {
        let mut total = 0u64;
        let mut n = 0u64;
        for c in text.chars() {
            if let Some(d) = c.to_digit(10) {
                n = n * 10 + d as u64;
                continue;
            }
            total += n * match c.to_ascii_uppercase() {
                'D' => 86400,
                'H' => 3600,
                'M' => 60,
                'S' => 1,
                _ => 0,
            };
            n = 0;
        }
        self.set_current_time();
        self.ns = self.ns.wrapping_sub(total * NS);
    }

    /// Current time, whole seconds.
    pub fn set_current_time(&mut self) {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        self.set_unix(now.as_secs() as i64);
    }

    pub fn from_system_time(t: std::time::SystemTime) -> RarTime {
        let mut r = RarTime::default();
        let ns = match t.duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_nanos() as u64,
            Err(e) => (e.duration().as_nanos() as u64).wrapping_neg(),
        };
        r.set_unix_ns(ns);
        r
    }

    pub fn to_system_time(&self) -> std::time::SystemTime {
        let ns = self.get_unix_ns() as i64;
        let d = std::time::Duration::from_nanos(ns.unsigned_abs());
        if ns >= 0 {
            std::time::UNIX_EPOCH + d
        } else {
            std::time::UNIX_EPOCH - d
        }
    }
}

pub fn is_leap_year(y: u32) -> bool {
    tz::is_leap(y as i64)
}
