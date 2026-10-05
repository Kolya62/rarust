// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! rarust: RAR archive extractor in pure Rust.
//!
//! Only the Rust standard library is used. The crate provides both the
//! `rarust` command line tool and a library for reading RAR archives.

// Some low level idioms are kept intentionally for bit exact behavior.
#![deny(unsafe_code)]
#![allow(clippy::needless_range_loop, clippy::too_many_arguments, clippy::mut_range_bound, clippy::manual_range_contains)]

pub mod archive;
pub mod cmddata;
pub mod consio;
pub mod crypt;
pub mod encname;
pub mod errhnd;
pub mod extinfo;
pub mod extract;
pub mod filcreat;
pub mod file;
pub mod filefn;
pub mod find;
pub mod getbits;
pub mod hash;
pub mod headers;
pub mod list;
pub mod loclang;
pub mod matchfn;
pub mod motw;
pub mod pathfn;
pub mod rawread;
pub mod rdwrfn;
pub mod recvol;
pub mod scantree;
pub mod strfn;
pub mod strlist;
pub mod timefn;
pub mod tz;
pub mod ui;
pub mod unicode;
#[cfg(unix)]
pub mod unixsig;
pub mod unpack;
pub mod volume;
#[cfg(windows)]
pub mod win32;
pub mod winsys;

use cmddata::{CmdRef, CommandData};
use consio::{eprintf, mprintf, MessageType};
use errhnd::*;

/// Process the parsed command.
pub fn process_command(cmd: &CmdRef) {
    let (command, arc_name_empty, single_char_violation) = {
        let c = cmd.borrow();
        let ch: Vec<char> = c.command.chars().collect();
        let viol = ch.len() > 1 && "FUADPXETK".contains(ch[0]);
        (c.command.clone(), c.arc_name.is_empty(), viol)
    };
    if single_char_violation || arc_name_empty {
        let code = if command.is_empty() { RARX_SUCCESS } else { RARX_USERERROR };
        cmd.borrow().out_help(code);
    }
    {
        let mut c = cmd.borrow_mut();
        let ext_pos = pathfn::get_ext_pos(&c.arc_name);
        if cfg!(unix) {
            if ext_pos.is_none() && (!filefn::file_exist(&c.arc_name) || filefn::is_dir(filefn::get_file_attr(&c.arc_name))) {
                c.arc_name.push_str(".rar");
            }
        } else if ext_pos.is_none() {
            c.arc_name.push_str(".rar");
        }
        if let Some(p) = ext_pos {
            let a: Vec<char> = c.arc_name[p..].chars().collect();
            if strfn::wcsnicomp_eq(&c.arc_name[p..], ".part", 5) && a.get(5).map(|c| c.is_ascii_digit()).unwrap_or(false) && !filefn::file_exist(&c.arc_name) {
                let n = format!("{}.rar", c.arc_name);
                if filefn::file_exist(&n) {
                    c.arc_name = n;
                }
            }
        }
    }
    let c0 = cmd.borrow().cmd_char();
    if !"AFUMD".contains(c0) && cmd.borrow().use_stdin.is_empty() {
        let (generate, mask) = {
            let c = cmd.borrow();
            (c.generate_arc_name, if !c.generate_mask.is_empty() { c.generate_mask.clone() } else { c.def_generate_mask.clone() })
        };
        if generate {
            let mut n = cmd.borrow().arc_name.clone();
            pathfn::generate_archive_name(&mut n, &mask, false);
            cmd.borrow_mut().arc_name = n;
        }
        let mut masks = strlist::StringList::new();
        masks.add_string(&cmd.borrow().arc_name);
        let recurse = cmd.borrow().recurse;
        let save_links = cmd.borrow().save_sym_links;
        let mut found = Vec::new();
        {
            let mut scan = scantree::ScanTree::new(&masks, recurse, save_links, scantree::ScanDirs::SkipDirs);
            let mut fd = find::FindData::default();
            while scan.get_next(&mut fd) == scantree::ScanCode::Success {
                found.push(fd.name.clone());
            }
        }
        for n in found {
            cmd.borrow_mut().add_arc_name(&n);
        }
    } else {
        let n = cmd.borrow().arc_name.clone();
        cmd.borrow_mut().add_arc_name(&n);
    }
    match c0 {
        'P' | 'X' | 'E' | 'T' => {
            let mut ex = extract::CmdExtract::new(cmd.clone());
            ex.do_extract();
        }
        'V' | 'L' => list::list_archive(cmd),
        _ => cmd.borrow().out_help(RARX_USERERROR),
    }
    let c = cmd.borrow();
    if !c.is_bare_output() {
        if c.msg_stream == MessageType::ErrOnly && consio::is_console_output_present() {
            eprintf("\n");
        } else {
            mprintf("\n");
        }
    }
}

/// Run rarust with command line arguments (excluding program name).
/// Returns the process exit code.
pub fn run(args: Vec<String>) -> i32 {
    let cmd = CommandData::new().into_ref();
    errhnd::set_signal_handlers(true);
    let code = run_catching(|| {
        cmd.borrow_mut().parse_command_line(true, &args);
        if !cmd.borrow().config_disabled {
            cmd.borrow_mut().read_config();
            cmd.borrow_mut().parse_env_var();
        }
        cmd.borrow_mut().parse_command_line(false, &args);
        if cfg!(windows) && cmd.borrow().shutdown != winsys::PowerMode::Keep {
            winsys::shutdown_register();
        }
        let (sound, all_yes, ms) = {
            let c = cmd.borrow();
            (c.sound, c.all_yes, c.msg_stream)
        };
        ui::ui_init(sound);
        set_silent(all_yes || ms == MessageType::Null);
        cmd.borrow().out_title();
        process_command(&cmd);
    });
    if cfg!(windows) && errhnd::is_shutdown_enabled() {
        let mode = cmd.try_borrow().map(|c| c.shutdown).unwrap_or_default();
        crate::winsys::shutdown(mode);
    }
    errhnd::set_main_exit();
    code
}
