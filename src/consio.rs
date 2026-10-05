// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Console input and output.

use crate::errhnd;
use crate::loclang::*;
use crate::strfn::{remove_lf, replace_esc, toupperw};
use crate::wfmt;
use std::cell::Cell;
use std::io::{IsTerminal, Write};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum MessageType {
    #[default]
    Stdout,
    Stderr,
    ErrOnly,
    Null,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum RarCharset {
    #[default]
    Default,
    Ansi,
    Oem,
    Unicode,
    Utf8,
}

thread_local! {
    static MSG_STREAM: Cell<MessageType> = const { Cell::new(MessageType::Stdout) };
    static PROHIBIT_INPUT: Cell<bool> = const { Cell::new(false) };
    static OUTPUT_PRESENT: Cell<bool> = const { Cell::new(false) };
}

pub fn set_console_msg_stream(t: MessageType) {
    MSG_STREAM.with(|m| m.set(t));
}

pub fn get_console_msg_stream() -> MessageType {
    MSG_STREAM.with(|m| m.get())
}

pub fn set_console_redirect_charset(_c: RarCharset) {}

pub fn prohibit_console_input() {
    PROHIBIT_INPUT.with(|p| p.set(true));
}

pub fn is_console_output_present() -> bool {
    OUTPUT_PRESENT.with(|p| p.get())
}

fn stdin_redirected() -> bool {
    !std::io::stdin().is_terminal()
}

fn out(to_stderr: bool, s: &str) {
    OUTPUT_PRESENT.with(|p| p.set(true));
    let s = replace_esc(s);
    if to_stderr {
        let mut e = std::io::stderr().lock();
        let _ = e.write_all(s.as_bytes());
        let _ = e.flush();
    } else {
        let mut o = std::io::stdout().lock();
        let _ = o.write_all(s.as_bytes());
        let _ = o.flush();
    }
}

/// Print a message to stdout (or stderr with -ierr).
pub fn mprintf(s: &str) {
    let m = get_console_msg_stream();
    if m == MessageType::Null || m == MessageType::ErrOnly {
        return;
    }
    out(m == MessageType::Stderr, s);
}

/// Print a message to stderr.
pub fn eprintf(s: &str) {
    if get_console_msg_stream() == MessageType::Null {
        return;
    }
    let _ = std::io::stdout().flush();
    out(true, s);
}

#[macro_export]
macro_rules! mprintf {
    ($($a:tt)*) => { $crate::consio::mprintf(&$crate::wfmt!($($a)*)) };
}

#[macro_export]
macro_rules! eprintf {
    ($($a:tt)*) => { $crate::consio::eprintf(&$crate::wfmt!($($a)*)) };
}

fn quit_if_input_prohibited() {
    if PROHIBIT_INPUT.with(|p| p.get()) {
        mprintf(MStdinNoInput);
        errhnd::exit(errhnd::RARX_FATAL);
    }
}

/// Read a line from stdin.
pub fn getwstr() -> String {
    let _ = std::io::stderr().flush();
    quit_if_input_prohibited();
    let mut s = String::new();
    errhnd::clear_os_error();
    match std::io::stdin().read_line(&mut s) {
        Ok(0) | Err(_) => errhnd::read_error("stdin"),
        _ => {}
    }
    remove_lf(&mut s);
    s
}

#[cfg(unix)]
fn set_tty_echo(on: bool) {
    if let Ok(tty) = std::fs::File::open("/dev/tty") {
        let _ = std::process::Command::new("stty")
            .arg(if on { "echo" } else { "-echo" })
            .stdin(tty)
            .status();
    }
}

#[cfg(windows)]
fn set_tty_echo(on: bool) {
    crate::winsys::set_console_echo(on);
}

#[cfg(not(any(unix, windows)))]
fn set_tty_echo(_on: bool) {}

fn get_password_text() -> String {
    quit_if_input_prohibited();
    if stdin_redirected() {
        return getwstr();
    }
    set_tty_echo(false);
    let mut s = String::new();
    let r = std::io::stdin().read_line(&mut s);
    set_tty_echo(true);
    if r.is_err() {
        s.clear();
    }
    remove_lf(&mut s);
    s
}

pub const MAXPASSWORD: usize = 512;

/// Password prompt types.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PasswordType {
    Global,
    File,
    Archive,
}

pub fn get_console_password(kind: PasswordType, file_name: &str) -> Option<String> {
    if !stdin_redirected() {
        crate::ui::ui_alarm(crate::ui::UiAlarm::Question);
    }
    loop {
        if kind == PasswordType::Global {
            eprintf(&wfmt!("\n%s: ", MAskPsw));
        } else {
            eprintf(&wfmt!(MAskPswFor, file_name));
        }
        let mut plain = get_password_text();
        if plain.is_empty() && kind == PasswordType::Global {
            return None;
        }
        if plain.chars().count() >= MAXPASSWORD {
            plain = plain.chars().take(MAXPASSWORD - 1).collect();
            crate::ui::ui_msg(crate::ui::UiMsg::TruncPsw((MAXPASSWORD - 1) as u32));
        }
        if !stdin_redirected() && kind == PasswordType::Global {
            eprintf(MReAskPsw);
            let cmp = get_password_text();
            if cmp.is_empty() || plain != cmp {
                eprintf(MNotMatchPsw);
                continue;
            }
        }
        return Some(plain);
    }
}

/// Ask a question with options encoded as "_Yes_No_All". Returns the
/// 1-based option number or 0 for invalid input.
pub fn ask(ask_str: &str) -> i32 {
    crate::ui::ui_alarm(crate::ui::UiAlarm::Question);
    let items: Vec<Vec<char>> = ask_str.split('_').skip(1).map(|s| s.chars().take(39).collect()).collect();
    let mut key_pos: Vec<usize> = Vec::new();
    for (n, item) in items.iter().enumerate() {
        let mut kp = 0;
        while kp < item.len() {
            let cur = item[kp];
            let mut found = false;
            for i in 0..n {
                if toupperw(items[i].get(key_pos[i]).copied().unwrap_or('\0')) == toupperw(cur) {
                    found = true;
                }
            }
            if !found && cur != ' ' {
                break;
            }
            kp += 1;
        }
        key_pos.push(kp);
    }
    let n = items.len();
    for (i, item) in items.iter().enumerate() {
        eprintf(if i == 0 { if n > 3 { "\n" } else { " " } } else { ", " });
        let kp = key_pos[i];
        let pre: String = item[..kp.min(item.len())].iter().collect();
        eprintf(&pre);
        let key = item.get(kp).copied().unwrap_or(' ');
        let rest: String = item.get(kp + 1..).map(|r| r.iter().collect()).unwrap_or_default();
        eprintf(&format!("[{}]{}", key, rest));
    }
    eprintf(" ");
    let s = getwstr();
    let ch = toupperw(s.chars().next().unwrap_or('\0'));
    for (i, item) in items.iter().enumerate() {
        if item.get(key_pos[i]).copied() == Some(ch) {
            return i as i32 + 1;
        }
    }
    0
}

fn is_comment_unsafe(data: &[char]) -> bool {
    for i in 0..data.len() {
        if data[i] == '\x1b' && data.get(i + 1) == Some(&'[') {
            for j in i + 2..data.len() {
                if data[j] == '"' {
                    return true;
                }
                if !data[j].is_ascii_digit() && data[j] != ';' {
                    break;
                }
            }
        }
    }
    false
}

pub fn out_comment(comment: &str) {
    let chars: Vec<char> = comment.chars().collect();
    if is_comment_unsafe(&chars) {
        return;
    }
    for chunk in chars.chunks(0x400) {
        let s: String = chunk.iter().collect();
        mprintf(&s);
    }
    mprintf("\n");
}
