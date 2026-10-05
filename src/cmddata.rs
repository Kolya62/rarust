// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Command line options and processing.

use crate::consio::{self, eprintf, mprintf, MessageType, PasswordType, RarCharset, MAXPASSWORD};
use crate::errhnd::{self, *};
use crate::find::{fast_find, FindData};
use crate::hash::HashType;
use crate::headers::{FileHeader, INT64NDF};
use crate::loclang::*;
use crate::matchfn::{cmp_name, MATCH_WILDSUBPATH};
use crate::pathfn::*;
use crate::strfn::*;
use crate::strlist::StringList;
use crate::timefn::RarTime;
use crate::ui::{ui_msg, UiMsg};
use crate::wfmt;
use std::cell::RefCell;
use std::rc::Rc;

pub type CmdRef = Rc<RefCell<CommandData>>;

pub const DEF_CONFIG_NAME: &str = ".rarrc";
pub const DEF_LOG_NAME: &str = ".rarlog";

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum PathExclMode {
    #[default]
    Unchanged,
    SkipWholePath,
    BasePath,
    SaveFullPath,
    AbsPath,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum DirFilterMode {
    #[default]
    IncludeAll,
    ExcludeAll,
    ExcludeEmpty,
    DirOnly,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum RecurseMode {
    #[default]
    None,
    Disable,
    Always,
    Wildcards,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum OverwriteMode {
    #[default]
    Default,
    All,
    None,
    AutoRename,
    ForceAsk,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ExtTimeMode {
    #[default]
    None,
    OneSec,
    Max,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum QOpenMode {
    None,
    #[default]
    Auto,
    Always,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum AppendArcName {
    #[default]
    None,
    DestPath,
    OwnSubdir,
    OwnDir,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
enum ListMode {
    #[default]
    Auto,
    Reject,
    Accept,
}

pub const NAMES_ORIGINALCASE: i32 = 0;
pub const NAMES_UPPERCASE: i32 = 1;
pub const NAMES_LOWERCASE: i32 = 2;

pub const SOLID_NONE: u32 = 0;
pub const SOLID_NORMAL: u32 = 1;
pub const SOLID_COUNT: u32 = 2;
pub const SOLID_FILEEXT: u32 = 4;
pub const SOLID_VOLUME_DEPENDENT: u32 = 8;
pub const SOLID_VOLUME_INDEPENDENT: u32 = 16;
pub const SOLID_RESET: u32 = 32;
pub const SOLID_BLOCK_SIZE: u32 = 64;

pub const VOLSIZE_AUTO: i64 = INT64NDF;

const DEFAULT_STORE_LIST: &str = "7z;arj;bz2;cab;gz;jpeg;jpg;lha;lz;lzh;mp3;rar;taz;tbz;tbz2;tgz;txz;xz;z;zip;zipx;zst;tzst";


#[derive(Clone, Debug)]
pub struct CommandData {
    // RAROptions.
    pub excl_file_attr: u32,
    pub incl_file_attr: u32,
    pub dir_mode: DirFilterMode,
    pub incl_attr_set: bool,
    pub win_size: u64,
    pub win_size_limit: u64,
    pub qopen_mode: QOpenMode,
    pub config_disabled: bool,
    pub comment_charset: RarCharset,
    pub filelist_charset: RarCharset,
    pub errlog_charset: RarCharset,
    pub redirect_charset: RarCharset,
    pub encrypt_headers: bool,
    pub skip_encrypted: bool,
    pub manual_password: bool,
    pub msg_stream: MessageType,
    pub sound: bool,
    pub overwrite: OverwriteMode,
    pub method: i32,
    pub hash_type: HashType,
    pub disable_percentage: bool,
    pub disable_copyright: bool,
    pub disable_done: bool,
    pub disable_names: bool,
    pub print_version: bool,
    pub solid: u32,
    pub solid_count: u32,
    pub solid_block_size: u64,
    pub clear_arc: bool,
    pub add_arc_only: bool,
    pub disable_comment: bool,
    pub fresh_files: bool,
    pub update_files: bool,
    pub excl_path: PathExclMode,
    pub recurse: RecurseMode,
    pub vol_size: i64,
    pub all_yes: bool,
    pub verbose_output: bool,
    pub disable_sort_solid: bool,
    pub convert_names: i32,
    pub process_owners: bool,
    pub save_sym_links: bool,
    pub save_hard_links: bool,
    pub absolute_links: bool,
    pub skip_sym_links: bool,
    pub priority: i32,
    pub sleep_time: i32,
    /// Power mode after completing the command (-ioff).
    pub shutdown: crate::winsys::PowerMode,
    pub keep_broken: bool,
    pub allow_incompat_names: bool,
    /// Set NTFS compression for files compressed in the source file system (-oc).
    pub set_compressed_attr: bool,
    /// Masks of files to receive the archive Mark of the Web (-om).
    pub motw_list: StringList,
    pub motw_all_fields: bool,
    pub open_shared: bool,
    pub delete_archive: bool,
    pub generate_arc_name: bool,
    pub generate_mask: String,
    pub def_generate_mask: String,
    pub sync_files: bool,
    pub ignore_general_attr: bool,
    pub file_mtime_before: RarTime,
    pub file_ctime_before: RarTime,
    pub file_atime_before: RarTime,
    pub file_mtime_before_or: bool,
    pub file_ctime_before_or: bool,
    pub file_atime_before_or: bool,
    pub file_mtime_after: RarTime,
    pub file_ctime_after: RarTime,
    pub file_atime_after: RarTime,
    pub file_mtime_after_or: bool,
    pub file_ctime_after_or: bool,
    pub file_atime_after_or: bool,
    pub file_size_less: i64,
    pub file_size_more: i64,
    pub lock: bool,
    pub test: bool,
    pub volume_pause: bool,
    pub version_control: u32,
    pub append_arc_name_to_path: AppendArcName,
    pub xmtime: ExtTimeMode,
    pub xctime: ExtTimeMode,
    pub xatime: ExtTimeMode,
    pub preserve_atime: bool,
    pub threads: u32,

    // CommandData.
    file_lists: bool,
    no_more_switches: bool,
    list_mode: ListMode,
    bare_output: bool,
    pub command: String,
    pub arc_name: String,
    pub extr_path: String,
    pub temp_path: String,
    pub sfx_module: String,
    pub comment_file: String,
    pub arc_path: String,
    pub excl_arc_path: String,
    pub log_name: String,
    pub email_to: String,
    pub use_stdin: String,
    pub file_args: StringList,
    pub excl_args: StringList,
    pub incl_args: StringList,
    pub arc_names: StringList,
    pub store_args: StringList,
    pub password: Option<String>,
}

impl Default for CommandData {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandData {
    pub fn new() -> Self {
        CommandData {
            excl_file_attr: 0,
            incl_file_attr: 0,
            dir_mode: DirFilterMode::IncludeAll,
            incl_attr_set: false,
            win_size: 0x2000000,
            win_size_limit: 0x100000000,
            qopen_mode: QOpenMode::Auto,
            config_disabled: false,
            comment_charset: RarCharset::Default,
            filelist_charset: RarCharset::Default,
            errlog_charset: RarCharset::Default,
            redirect_charset: RarCharset::Default,
            encrypt_headers: false,
            skip_encrypted: false,
            manual_password: false,
            msg_stream: MessageType::Stdout,
            sound: false,
            overwrite: OverwriteMode::Default,
            method: 3,
            hash_type: HashType::Crc32,
            disable_percentage: false,
            disable_copyright: false,
            disable_done: false,
            disable_names: false,
            print_version: false,
            solid: 0,
            solid_count: 0,
            solid_block_size: 0,
            clear_arc: false,
            add_arc_only: false,
            disable_comment: false,
            fresh_files: false,
            update_files: false,
            excl_path: PathExclMode::Unchanged,
            recurse: RecurseMode::None,
            vol_size: 0,
            all_yes: false,
            verbose_output: false,
            disable_sort_solid: false,
            convert_names: NAMES_ORIGINALCASE,
            process_owners: false,
            save_sym_links: false,
            save_hard_links: false,
            absolute_links: false,
            skip_sym_links: false,
            priority: 0,
            sleep_time: 0,
            shutdown: Default::default(),
            keep_broken: false,
            allow_incompat_names: false,
            set_compressed_attr: false,
            motw_list: StringList::new(),
            motw_all_fields: false,
            open_shared: false,
            delete_archive: false,
            generate_arc_name: false,
            generate_mask: String::new(),
            def_generate_mask: String::new(),
            sync_files: false,
            ignore_general_attr: false,
            file_mtime_before: RarTime::default(),
            file_ctime_before: RarTime::default(),
            file_atime_before: RarTime::default(),
            file_mtime_before_or: false,
            file_ctime_before_or: false,
            file_atime_before_or: false,
            file_mtime_after: RarTime::default(),
            file_ctime_after: RarTime::default(),
            file_atime_after: RarTime::default(),
            file_mtime_after_or: false,
            file_ctime_after_or: false,
            file_atime_after_or: false,
            file_size_less: INT64NDF,
            file_size_more: INT64NDF,
            lock: false,
            test: false,
            volume_pause: false,
            version_control: 0,
            append_arc_name_to_path: AppendArcName::None,
            xmtime: ExtTimeMode::Max,
            xctime: ExtTimeMode::None,
            xatime: ExtTimeMode::None,
            preserve_atime: false,
            threads: std::thread::available_parallelism().map(|n| n.get() as u32).unwrap_or(1).min(64),
            file_lists: false,
            no_more_switches: false,
            list_mode: ListMode::Auto,
            bare_output: false,
            command: String::new(),
            arc_name: String::new(),
            extr_path: String::new(),
            temp_path: String::new(),
            sfx_module: String::new(),
            comment_file: String::new(),
            arc_path: String::new(),
            excl_arc_path: String::new(),
            log_name: String::new(),
            email_to: String::new(),
            use_stdin: String::new(),
            file_args: StringList::new(),
            excl_args: StringList::new(),
            incl_args: StringList::new(),
            arc_names: StringList::new(),
            store_args: StringList::new(),
            password: None,
        }
    }

    pub fn into_ref(self) -> CmdRef {
        Rc::new(RefCell::new(self))
    }

    pub fn cmd_char(&self) -> char {
        self.command.chars().next().unwrap_or('\0')
    }

    pub fn password_set(&self) -> bool {
        self.password.as_ref().map(|p| !p.is_empty()).unwrap_or(false)
    }

    pub fn password_clean(&mut self) {
        self.password = None;
    }

    fn set_password(&mut self, p: &str) {
        if p.chars().count() >= MAXPASSWORD {
            ui_msg(UiMsg::TruncPsw((MAXPASSWORD - 1) as u32));
        }
        self.password = Some(p.chars().take(MAXPASSWORD - 1).collect());
    }

    /// Parse command line arguments, excluding program name.
    pub fn parse_command_line(&mut self, preprocess: bool, args: &[String]) {
        self.command.clear();
        self.no_more_switches = false;
        for a in args {
            if preprocess {
                self.preprocess_arg(a);
            } else {
                self.parse_arg(a);
            }
        }
        if !preprocess {
            self.parse_done();
        }
    }

    pub fn is_switch(c: char) -> bool {
        if cfg!(unix) {
            c == '-'
        } else {
            c == '-' || c == '/'
        }
    }

    pub fn parse_arg(&mut self, arg: &str) {
        let a = chars(arg);
        if Self::is_switch(at(&a, 0)) && !self.no_more_switches {
            if at(&a, 1) == '-' && at(&a, 2) == '\0' {
                self.no_more_switches = true;
            } else {
                let sw: String = a[1..].iter().collect();
                self.process_switch(&sw);
            }
            return;
        }
        if self.command.is_empty() {
            let mut c: Vec<char> = a.clone();
            if !c.is_empty() {
                c[0] = toupperw(c[0]);
            }
            self.command = c.iter().collect();
            if at(&c, 0) != 'I' && at(&c, 0) != 'S' {
                self.command = wcsupper(&self.command);
            }
            if at(&c, 0) == 'P' {
                self.msg_stream = MessageType::ErrOnly;
                consio::set_console_msg_stream(MessageType::ErrOnly);
            }
            return;
        }
        if self.arc_name.is_empty() {
            self.arc_name = arg.to_string();
            return;
        }
        let len = a.len();
        let end = if len == 0 { '\0' } else { a[len - 1] };
        let mut folder_arg = is_drive_div(end) || is_path_div(end);
        if is_drive_letter(arg) && at(&a, 2) == '.' && (at(&a, 3) == '\0' || at(&a, 3) == '.' && at(&a, 4) == '\0') {
            folder_arg = true;
        }
        let l = len;
        if l > 0
            && a[l - 1] == '.'
            && (l == 1 || l >= 2 && (is_path_div(a[l - 2]) || a[l - 2] == '.' && (l == 2 || l >= 3 && is_path_div(a[l - 3]))))
        {
            folder_arg = true;
        }
        let cmd_char = toupperw(self.cmd_char());
        let add = "AFUM".contains(cmd_char);
        let extract = cmd_char == 'X' || cmd_char == 'E';
        let repair = cmd_char == 'R' && self.command.chars().count() == 1;
        if folder_arg && !add {
            self.extr_path = arg.to_string();
        } else if (add || cmd_char == 'T') && (at(&a, 0) != '@' || self.list_mode == ListMode::Reject) {
            self.file_args.add_string(arg);
        } else {
            let mut fd = FindData::default();
            let found = fast_find(arg, &mut fd, false);
            let rest: String = a.iter().skip(1).collect();
            if (!found || self.list_mode == ListMode::Accept)
                && self.list_mode != ListMode::Reject
                && at(&a, 0) == '@'
                && !is_wildcard(&rest)
            {
                self.file_lists = true;
                read_text_file(&rest, &mut self.file_args, false, true);
            } else if found && fd.is_dir && (extract || repair) && self.extr_path.is_empty() {
                self.extr_path = arg.to_string();
                add_end_slash(&mut self.extr_path);
            } else {
                self.file_args.add_string(arg);
            }
        }
    }

    pub fn parse_done(&mut self) {
        if self.file_args.items_count() == 0 && !self.file_lists {
            self.file_args.add_string("*");
        }
        let c = toupperw(self.cmd_char());
        let extract = c == 'X' || c == 'E' || c == 'P';
        if self.test && extract {
            self.test = false;
        }
        let c1 = self.command.chars().nth(1).unwrap_or('\0');
        if (c == 'L' || c == 'V') && c1 == 'B' {
            self.bare_output = true;
        }
    }

    pub fn is_bare_output(&self) -> bool {
        self.bare_output
    }

    pub fn parse_env_var(&mut self) {
        if let Some(v) = std::env::var_os("RARINISWITCHES") {
            let s = crate::unicode::from_os(&v);
            self.process_switches_string(&s);
        }
    }

    pub fn preprocess_arg(&mut self, arg: &str) {
        let a = chars(arg);
        if Self::is_switch(at(&a, 0)) && !self.no_more_switches {
            let sw: String = a[1..].iter().collect();
            if sw == "-" {
                self.no_more_switches = true;
            }
            if wcsicomp_eq(&sw, "cfg-") {
                self.process_switch(&sw);
            }
            if wcsnicomp_eq(&sw, "ilog", 4) {
                self.process_switch(&sw);
            }
            if wcsnicomp_eq(&sw, "sc", 2) {
                self.process_switch(&sw);
            }
        } else if self.command.is_empty() {
            self.command = arg.to_string();
        }
    }

    pub fn read_config(&mut self) {
        let mut list = StringList::new();
        if read_text_file(DEF_CONFIG_NAME, &mut list, true, false) {
            while let Some(s) = list.get_string() {
                let s = s.trim_start_matches([' ', '\t']).to_string();
                if wcsnicomp_eq(&s, "switches=", 9) {
                    let rest: String = s.chars().skip(9).collect();
                    self.process_switches_string(&rest);
                }
                if !self.command.is_empty() {
                    let mut cmd: Vec<char> = self.command.chars().take(15).collect();
                    let c0 = toupperw(at(&cmd, 0));
                    let c1 = toupperw(at(&cmd, 1));
                    if "ILMSV".contains(c0) {
                        cmd.truncate(1);
                    }
                    if c0 == 'R' && (c1 == 'R' || c1 == 'V') {
                        cmd.truncate(2);
                    }
                    let sw_name = format!("switches_{}=", cmd.iter().collect::<String>());
                    let l = sw_name.chars().count();
                    if wcsnicomp_eq(&s, &sw_name, l) {
                        let rest: String = s.chars().skip(l).collect();
                        self.process_switches_string(&rest);
                    }
                }
            }
        }
    }

    pub fn process_switches_string(&mut self, s: &str) {
        let v = chars(s);
        let mut pos = 0;
        while let Some(par) = get_cmd_param(&v, &mut pos) {
            let p = chars(&par);
            if Self::is_switch(at(&p, 0)) {
                self.process_switch(&p[1..].iter().collect::<String>());
            } else {
                mprintf(&wfmt!(MSwSyntaxError, par));
                errhnd::exit(RARX_USERERROR);
            }
        }
    }

    fn bad_switch(&self, sw: &str) -> ! {
        mprintf(&wfmt!(MUnknownOption, sw));
        errhnd::exit(RARX_USERERROR)
    }

    pub fn process_switch(&mut self, switch: &str) {
        let s = chars(switch);
        let s1 = toupperw(at(&s, 1));
        let tail = |n: usize| -> String { s.iter().skip(n).collect() };
        match toupperw(at(&s, 0)) {
            '@' => self.list_mode = if at(&s, 1) == '+' { ListMode::Accept } else { ListMode::Reject },
            'A' => match s1 {
                'C' => self.clear_arc = true,
                'D' => match at(&s, 2) {
                    '\0' => self.append_arc_name_to_path = AppendArcName::DestPath,
                    '1' => self.append_arc_name_to_path = AppendArcName::OwnSubdir,
                    '2' => self.append_arc_name_to_path = AppendArcName::OwnDir,
                    _ => {}
                },
                'G' => {
                    if at(&s, 2) == '-' && at(&s, 3) == '\0' {
                        self.generate_arc_name = false;
                    } else if toupperw(at(&s, 2)) == 'F' {
                        self.def_generate_mask = tail(3).chars().take(127).collect();
                    } else {
                        self.generate_arc_name = true;
                        self.generate_mask = tail(2).chars().take(127).collect();
                    }
                }
                'I' => self.ignore_general_attr = true,
                'M' => match toupperw(at(&s, 2)) {
                    '\0' | 'S' | 'R' => {}
                    _ => self.bad_switch(switch),
                },
                'O' => self.add_arc_only = true,
                'P' => self.arc_path = slash_to_native(&tail(2)),
                'S' => self.sync_files = true,
                _ => self.bad_switch(switch),
            },
            'C' => {
                if at(&s, 2) != '\0' {
                    if wcsicomp_eq(&tail(1), "FG-") {
                        self.config_disabled = true;
                    } else {
                        self.bad_switch(switch);
                    }
                } else {
                    match s1 {
                        '-' => self.disable_comment = true,
                        'U' => self.convert_names = NAMES_UPPERCASE,
                        'L' => self.convert_names = NAMES_LOWERCASE,
                        _ => self.bad_switch(switch),
                    }
                }
            }
            'D' => {
                if at(&s, 2) != '\0' {
                    self.bad_switch(switch);
                }
                match s1 {
                    'S' => self.disable_sort_solid = true,
                    'H' => self.open_shared = true,
                    'A' => self.delete_archive = true,
                    _ => self.bad_switch(switch),
                }
            }
            'E' => match s1 {
                'P' => match at(&s, 2) {
                    '\0' => self.excl_path = PathExclMode::SkipWholePath,
                    '1' => self.excl_path = PathExclMode::BasePath,
                    '2' => self.excl_path = PathExclMode::SaveFullPath,
                    '3' => self.excl_path = PathExclMode::AbsPath,
                    '4' => self.excl_arc_path = slash_to_native(&tail(3)),
                    _ => self.bad_switch(switch),
                },
                _ => {
                    if at(&s, 1) == '+' {
                        let mut dm = self.dir_mode;
                        self.incl_file_attr |= get_excl_attr(&tail(2), false, &mut dm);
                        self.dir_mode = dm;
                        self.incl_attr_set = true;
                    } else {
                        let mut dm = self.dir_mode;
                        self.excl_file_attr |= get_excl_attr(&tail(1), true, &mut dm);
                        self.dir_mode = dm;
                    }
                }
            },
            'F' => {
                if at(&s, 1) == '\0' {
                    self.fresh_files = true;
                } else {
                    self.bad_switch(switch);
                }
            }
            'H' => match s1 {
                'P' => {
                    self.encrypt_headers = true;
                    if at(&s, 2) != '\0' {
                        self.set_password(&tail(2));
                    } else if !self.password_set() {
                        if let Some(p) = crate::consio::get_console_password(PasswordType::Global, "") {
                            self.password = Some(p);
                        }
                        eprintf("\n");
                    }
                }
                _ => self.bad_switch(switch),
            },
            'I' => {
                let t = tail(1);
                if wcsnicomp_eq(&t, "LOG", 3) {
                    self.log_name = if at(&s, 4) != '\0' { tail(4) } else { DEF_LOG_NAME.to_string() };
                } else if wcsnicomp_eq(&t, "SND", 3) {
                    self.sound = at(&s, 4) != '-';
                } else if wcsicomp_eq(&t, "ERR") {
                    self.msg_stream = MessageType::Stderr;
                    consio::set_console_msg_stream(MessageType::Stderr);
                } else if wcsnicomp_eq(&t, "EML", 3) {
                    self.email_to = if at(&s, 4) != '\0' { tail(4) } else { "@".to_string() };
                } else if wcsicomp_eq(&t, "M") {
                    self.verbose_output = true;
                } else if wcsicomp_eq(&t, "NUL") {
                    self.msg_stream = MessageType::Null;
                    consio::set_console_msg_stream(MessageType::Null);
                } else if s1 == 'D' {
                    for &c in &s[2..] {
                        match toupperw(c) {
                            'Q' => {
                                self.msg_stream = MessageType::ErrOnly;
                                consio::set_console_msg_stream(MessageType::ErrOnly);
                            }
                            'C' => self.disable_copyright = true,
                            'D' => self.disable_done = true,
                            'P' => self.disable_percentage = true,
                            'N' => self.disable_names = true,
                            'V' => self.verbose_output = true,
                            _ => {}
                        }
                    }
                } else if wcsnicomp_eq(&t, "OFF", 3) {
                    use crate::winsys::PowerMode;
                    match at(&s, 4) {
                        '\0' | '1' => self.shutdown = PowerMode::Off,
                        '2' => self.shutdown = PowerMode::Hibernate,
                        '3' => self.shutdown = PowerMode::Sleep,
                        '4' => self.shutdown = PowerMode::Restart,
                        _ => {}
                    }
                } else if wcsicomp_eq(&t, "VER") {
                    self.print_version = true;
                }
            }
            'K' => match s1 {
                'B' => self.keep_broken = true,
                '\0' => self.lock = true,
                _ => {}
            },
            'M' => match s1 {
                'C' => {}
                'D' => {
                    let set_limit = toupperw(at(&s, 2)) == 'X';
                    let mut size = atoiw(&tail(if set_limit { 3 } else { 2 })).max(0) as u64;
                    let mut last = toupperw(s.last().copied().unwrap_or('\0'));
                    if last.is_ascii_digit() {
                        last = if set_limit { 'G' } else { 'M' };
                    }
                    match last {
                        'K' => size *= 1024,
                        'M' => size *= 1024 * 1024,
                        'G' => size *= 1024 * 1024 * 1024,
                        _ => self.bad_switch(switch),
                    }
                    let (sz, _) = crate::archive::get_win_size(size);
                    if sz == 0 || sz <= 0x100000000 && !sz.is_power_of_two() {
                        self.bad_switch(switch);
                    } else if set_limit {
                        self.win_size_limit = sz;
                    } else {
                        self.win_size = sz;
                    }
                }
                'E' => {
                    if toupperw(at(&s, 2)) == 'S' && at(&s, 3) == '\0' {
                        self.skip_encrypted = true;
                    }
                }
                'L' | 'M' => {}
                'S' => {
                    let t = if at(&s, 2) == '\0' { DEFAULT_STORE_LIST.to_string() } else { tail(2) };
                    let mut list = std::mem::take(&mut self.store_args);
                    get_brief_mask_list(&t, &mut list);
                    self.store_args = list;
                }
                'T' => {
                    let t = atoiw(&tail(2));
                    if !(1..=64).contains(&t) {
                        self.bad_switch(switch);
                    }
                    self.threads = t as u32;
                }
                _ => {
                    self.method = at(&s, 1) as i32 - '0' as i32;
                    if self.method > 5 || self.method < 0 {
                        self.bad_switch(switch);
                    }
                }
            },
            'N' | 'X' => {
                if at(&s, 1) != '\0' {
                    let is_n = toupperw(at(&s, 0)) == 'N';
                    let mut args = std::mem::take(if is_n { &mut self.incl_args } else { &mut self.excl_args });
                    if at(&s, 1) == '@' && !is_wildcard(switch) {
                        read_text_file(&tail(2), &mut args, false, true);
                    } else {
                        args.add_string(&tail(1));
                    }
                    if is_n {
                        self.incl_args = args;
                    } else {
                        self.excl_args = args;
                    }
                }
            }
            'O' => match s1 {
                '+' => self.overwrite = OverwriteMode::All,
                '-' => self.overwrite = OverwriteMode::None,
                '\0' => self.overwrite = OverwriteMode::ForceAsk,
                'H' => self.save_hard_links = true,
                'L' => {
                    self.save_sym_links = true;
                    for &c in &s[2..] {
                        match toupperw(c) {
                            'A' => self.absolute_links = true,
                            '-' => self.skip_sym_links = true,
                            _ => self.bad_switch(switch),
                        }
                    }
                }
                'P' => {
                    self.extr_path = tail(2);
                    add_end_slash(&mut self.extr_path);
                }
                'R' => self.overwrite = OverwriteMode::AutoRename,
                'W' => self.process_owners = true,
                'N' if cfg!(windows) => {
                    if toupperw(at(&s, 2)) == 'I' {
                        self.allow_incompat_names = true;
                    }
                }
                'C' if cfg!(windows) => self.set_compressed_attr = true,
                'M' if cfg!(windows) => {
                    self.motw_all_fields = at(&s, 2) == '1';
                    if at(&s, 2) == '-' {
                        self.motw_list.reset();
                    } else {
                        let masks: String = match s.iter().position(|&c| c == '=') {
                            Some(p) => s[p + 1..].iter().take_while(|&&c| c != '\0').collect(),
                            None => "*".to_string(),
                        };
                        get_brief_mask_list(&masks, &mut self.motw_list);
                    }
                }
                _ => self.bad_switch(switch),
            },
            'P' => {
                if at(&s, 1) == '\0' {
                    if let Some(p) = crate::consio::get_console_password(PasswordType::Global, "") {
                        self.password = Some(p);
                    }
                    eprintf("\n");
                } else {
                    self.set_password(&tail(1));
                }
            }
            'Q' => {
                if s1 == 'O' {
                    match toupperw(at(&s, 2)) {
                        '\0' => self.qopen_mode = QOpenMode::Auto,
                        '-' => self.qopen_mode = QOpenMode::None,
                        '+' => self.qopen_mode = QOpenMode::Always,
                        _ => self.bad_switch(switch),
                    }
                } else {
                    self.bad_switch(switch);
                }
            }
            'R' => match s1 {
                '\0' => self.recurse = RecurseMode::Always,
                '-' => self.recurse = RecurseMode::Disable,
                '0' => self.recurse = RecurseMode::Wildcards,
                'I' => {
                    self.priority = atoiw(&tail(2)) as i32;
                    if self.priority < 0 || self.priority > 15 {
                        self.bad_switch(switch);
                    }
                    if let Some(p) = switch.find(':') {
                        self.sleep_time = atoiw(&switch[p + 1..]) as i32;
                        if self.sleep_time > 1000 {
                            self.bad_switch(switch);
                        }
                    }
                    if cfg!(windows) {
                        crate::winsys::set_priority(self.priority, self.sleep_time);
                    }
                }
                _ => {}
            },
            'S' => {
                if at(&s, 1).is_ascii_digit() {
                    self.solid |= SOLID_COUNT;
                    self.solid_count = atoiw(&tail(1)) as u32;
                } else {
                    match s1 {
                        '\0' | '+' | '=' => {
                            self.solid |= SOLID_NORMAL;
                            if at(&s, 1) == '=' {
                                let mut par: u64 = 0;
                                for &c in &s[2..] {
                                    if c.is_ascii_digit() {
                                        par = par * 10 + (c as u64 - '0' as u64);
                                    }
                                    match toupperw(c) {
                                        '-' => self.solid = SOLID_NONE,
                                        'D' => self.solid |= SOLID_VOLUME_DEPENDENT,
                                        'E' => self.solid |= SOLID_FILEEXT,
                                        'F' => {
                                            self.solid |= SOLID_COUNT;
                                            self.solid_count = par as u32;
                                        }
                                        'K' => {
                                            self.solid |= SOLID_BLOCK_SIZE;
                                            self.solid_block_size = par * 1024;
                                        }
                                        'M' => {
                                            self.solid |= SOLID_BLOCK_SIZE;
                                            self.solid_block_size = par * 1024 * 1024;
                                        }
                                        'G' => {
                                            self.solid |= SOLID_BLOCK_SIZE;
                                            self.solid_block_size = par * 1024 * 1024 * 1024;
                                        }
                                        'R' => self.solid = SOLID_RESET,
                                        'V' => self.solid |= SOLID_VOLUME_INDEPENDENT,
                                        _ => {}
                                    }
                                }
                            }
                        }
                        '-' => self.solid = SOLID_NONE,
                        'E' => self.solid |= SOLID_FILEEXT,
                        'V' => {
                            self.solid |= if at(&s, 2) == '-' { SOLID_VOLUME_DEPENDENT } else { SOLID_VOLUME_INDEPENDENT }
                        }
                        'D' => self.solid |= SOLID_VOLUME_DEPENDENT,
                        'I' => {
                            consio::prohibit_console_input();
                            self.use_stdin = if at(&s, 2) != '\0' { tail(2) } else { "stdin".to_string() };
                        }
                        'L' => {
                            if at(&s, 2).is_ascii_digit() {
                                self.file_size_less = get_mod_size(&tail(2), 1);
                            }
                        }
                        'M' => {
                            if at(&s, 2).is_ascii_digit() {
                                self.file_size_more = get_mod_size(&tail(2), 1);
                            }
                        }
                        'C' => {
                            let rch = match toupperw(at(&s, 2)) {
                                'A' => RarCharset::Ansi,
                                'O' => RarCharset::Oem,
                                'U' => RarCharset::Unicode,
                                'F' => RarCharset::Utf8,
                                _ => self.bad_switch(switch),
                            };
                            if at(&s, 3) == '\0' {
                                self.comment_charset = rch;
                                self.filelist_charset = rch;
                                self.errlog_charset = rch;
                                self.redirect_charset = rch;
                            } else {
                                for &c in &s[3..] {
                                    match toupperw(c) {
                                        'C' => self.comment_charset = rch,
                                        'L' => self.filelist_charset = rch,
                                        'R' => self.redirect_charset = rch,
                                        _ => self.bad_switch(switch),
                                    }
                                }
                            }
                            consio::set_console_redirect_charset(self.redirect_charset);
                        }
                        _ => self.bad_switch(switch),
                    }
                }
            }
            'T' => match s1 {
                'O' => self.set_time_filters(&tail(2), true, true),
                'N' => self.set_time_filters(&tail(2), false, true),
                'B' => self.set_time_filters(&tail(2), true, false),
                'A' => self.set_time_filters(&tail(2), false, false),
                'S' => self.set_store_time_mode(&tail(2)),
                '-' => self.test = false,
                '\0' => self.test = true,
                _ => self.bad_switch(switch),
            },
            'U' => {
                if at(&s, 1) == '\0' {
                    self.update_files = true;
                } else {
                    self.bad_switch(switch);
                }
            }
            'V' => match s1 {
                'P' => self.volume_pause = true,
                'E' => {
                    if toupperw(at(&s, 2)) == 'R' {
                        self.version_control = (atoiw(&tail(3)) + 1) as u32;
                    }
                }
                '-' => self.vol_size = 0,
                _ => self.vol_size = VOLSIZE_AUTO,
            },
            'W' => {
                self.temp_path = tail(1);
                add_end_slash(&mut self.temp_path);
            }
            'Y' => self.all_yes = true,
            'Z' => {
                self.comment_file = if at(&s, 1) == '\0' { "stdin".to_string() } else { tail(1) };
            }
            '?' => self.out_help(RARX_SUCCESS),
            _ => self.bad_switch(switch),
        }
    }

    fn set_time_filters(&mut self, m: &str, before: bool, age: bool) {
        let v = chars(m);
        let mut mode_or = false;
        let mut time_mods = false;
        let mut si = 0;
        while si < v.len() && "MCAOmcao".contains(v[si]) {
            if v[si] == 'o' || v[si] == 'O' {
                mode_or = true;
            } else {
                time_mods = true;
            }
            si += 1;
        }
        let text: String = v[si..].iter().collect();
        let mods: Vec<char> = if !time_mods { vec!['m'] } else { v.clone() };
        for &c in mods.iter() {
            if !"MCAOmcao".contains(c) {
                break;
            }
            let set = |t: &mut RarTime| {
                if age {
                    t.set_age_text(&text)
                } else {
                    t.set_iso_text(&text)
                }
            };
            match toupperw(c) {
                'M' => {
                    if before {
                        set(&mut self.file_mtime_before);
                        self.file_mtime_before_or = mode_or;
                    } else {
                        set(&mut self.file_mtime_after);
                        self.file_mtime_after_or = mode_or;
                    }
                }
                'C' => {
                    if before {
                        set(&mut self.file_ctime_before);
                        self.file_ctime_before_or = mode_or;
                    } else {
                        set(&mut self.file_ctime_after);
                        self.file_ctime_after_or = mode_or;
                    }
                }
                'A' => {
                    if before {
                        set(&mut self.file_atime_before);
                        self.file_atime_before_or = mode_or;
                    } else {
                        set(&mut self.file_atime_after);
                        self.file_atime_after_or = mode_or;
                    }
                }
                _ => {}
            }
        }
    }

    fn set_store_time_mode(&mut self, s: &str) {
        let v = chars(s);
        let mut i = 0;
        let c0 = at(&v, 0);
        if c0 == '\0' || c0.is_ascii_digit() || c0 == '-' || c0 == '+' {
            let mut mode = ExtTimeMode::Max;
            if c0 == '-' {
                mode = ExtTimeMode::None;
            }
            if c0 == '1' {
                mode = ExtTimeMode::OneSec;
            }
            self.xmtime = mode;
            self.xctime = mode;
            self.xatime = mode;
            i += 1;
        }
        while i < v.len() {
            let mut mode = ExtTimeMode::Max;
            if at(&v, i + 1) == '-' {
                mode = ExtTimeMode::None;
            }
            if at(&v, i + 1) == '1' {
                mode = ExtTimeMode::OneSec;
            }
            match toupperw(v[i]) {
                'M' => self.xmtime = mode,
                'C' => self.xctime = mode,
                'A' => self.xatime = mode,
                'P' => self.preserve_atime = true,
                _ => {}
            }
            i += 1;
        }
    }

    /// Return true if file must be excluded by -x or not included by -n.
    pub fn excl_check(&self, check_name: &str, dir: bool, check_full_path: bool, check_incl_list: bool) -> bool {
        if Self::check_args(&self.excl_args, dir, check_name, check_full_path, MATCH_WILDSUBPATH) {
            return true;
        }
        if !check_incl_list || self.incl_args.items_count() == 0 {
            return false;
        }
        if Self::check_args(&self.incl_args, dir, check_name, check_full_path, MATCH_WILDSUBPATH) {
            return false;
        }
        true
    }

    pub fn check_args(args: &StringList, dir: bool, check_name: &str, check_full_path: bool, match_mode: u32) -> bool {
        let (_, name) = convert_path(check_name);
        let mut full_name = String::new();
        for cur in args.items() {
            let mut cur_mask = cur.clone();
            let last = get_last_char(&cur_mask);
            let dir_mask = is_path_div(last);
            if dir {
                if dir_mask {
                    cur_mask.pop();
                } else {
                    let n = point_to_name(&cur_mask);
                    if is_wildcard(n) && n != "*" && n != "*.*" {
                        continue;
                    }
                }
            } else if dir_mask {
                cur_mask.push('*');
            }
            if check_full_path && is_full_path(&cur_mask) {
                if full_name.is_empty() {
                    full_name = convert_name_to_full(check_name);
                }
                if cmp_name(&cur_mask, &full_name, match_mode) {
                    return true;
                }
            } else {
                let mut cur_name = name.clone();
                let (_, cmp_mask) = convert_path(&cur_mask);
                let cm = chars(&cmp_mask);
                if at(&cm, 0) == '*' && is_path_div(at(&cm, 1)) {
                    cur_name = format!(".{}{}", CPATHDIVIDER, name);
                }
                if cmp_name(&cmp_mask, &cur_name, match_mode) {
                    return true;
                }
            }
        }
        false
    }

    /// Return true if file must be excluded by time filters.
    pub fn time_check(&self, ftm: &RarTime, ftc: &RarTime, fta: &RarTime) -> bool {
        let mut filter_or = false;
        let checks: [(&RarTime, &RarTime, bool, bool); 6] = [
            (&self.file_mtime_before, ftm, self.file_mtime_before_or, true),
            (&self.file_mtime_after, ftm, self.file_mtime_after_or, false),
            (&self.file_ctime_before, ftc, self.file_ctime_before_or, true),
            (&self.file_ctime_after, ftc, self.file_ctime_after_or, false),
            (&self.file_atime_before, fta, self.file_atime_before_or, true),
            (&self.file_atime_after, fta, self.file_atime_after_or, false),
        ];
        for (filter, t, or, before) in checks {
            if filter.is_set() {
                let not_matched = if before { *t >= *filter } else { *t < *filter };
                if not_matched {
                    if or {
                        filter_or = true;
                    } else {
                        return true;
                    }
                } else if or {
                    return false;
                }
            }
        }
        filter_or
    }

    pub fn size_check(&self, size: i64) -> bool {
        if size == INT64NDF {
            return false;
        }
        if self.file_size_less != INT64NDF && size >= self.file_size_less {
            return true;
        }
        if self.file_size_more != INT64NDF && size <= self.file_size_more {
            return true;
        }
        false
    }

    /// Return 0 if file must not be processed or number of matched argument.
    pub fn is_process_file(&self, fh: &FileHeader, exact_match: Option<&mut bool>, match_type: u32, matched_arg: Option<&mut String>) -> usize {
        let mut matched_arg = matched_arg;
        if let Some(m) = matched_arg.as_deref_mut() {
            m.clear();
        }
        let dir = fh.dir;
        if self.excl_check(&fh.file_name, dir, false, true) {
            return 0;
        }
        if self.time_check(&fh.mtime, &fh.ctime, &fh.atime) {
            return 0;
        }
        if (fh.file_attr & self.excl_file_attr) != 0 || fh.dir && self.dir_mode == DirFilterMode::ExcludeAll {
            return 0;
        }
        if self.incl_attr_set && (fh.file_attr & self.incl_file_attr) == 0 && (!fh.dir || self.dir_mode != DirFilterMode::DirOnly) {
            return 0;
        }
        if !dir && self.size_check(fh.unp_size) {
            return 0;
        }
        for (i, arg) in self.file_args.items().iter().enumerate() {
            if cmp_name(arg, &fh.file_name, match_type) {
                if let Some(e) = exact_match {
                    *e = wcsicompc_eq(arg, &fh.file_name);
                }
                if let Some(m) = matched_arg {
                    *m = arg.clone();
                }
                return i + 1;
            }
        }
        0
    }

    pub fn out_title(&self) {
        if self.bare_output || self.disable_copyright && !self.print_version {
            return;
        }
        thread_local!(static SHOWN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) });
        if SHOWN.with(|s| s.replace(true)) {
            return;
        }
        let version = env!("CARGO_PKG_VERSION").to_string();
        if self.print_version {
            mprintf(&format!("{}\n", version));
            std::process::exit(0);
        }
        mprintf(&wfmt!(MUCopyright, version));
    }

    pub fn out_help(&self, exit_code: i32) -> ! {
        self.out_title();
        let help: &[&str] = &[
            MRARTitle1, MRARTitle2, MCHelpCmd, MCHelpCmdE, MCHelpCmdL, MCHelpCmdP, MCHelpCmdT, MCHelpCmdV, MCHelpCmdX,
            MCHelpSw, MCHelpSwm, MCHelpSwAT, MCHelpSwAC, MCHelpSwAD, MCHelpSwAG, MCHelpSwAI, MCHelpSwAP, MCHelpSwCm,
            MCHelpSwCFGm, MCHelpSwCL, MCHelpSwCU, MCHelpSwDA, MCHelpSwDH, MCHelpSwEP, MCHelpSwEP3, MCHelpSwEP4,
            MCHelpSwF, MCHelpSwIDP, MCHelpSwIERR, MCHelpSwINUL, MCHelpSwIOFF, MCHelpSwKB, MCHelpSwME, MCHelpSwMLP,
            MCHelpSwN, MCHelpSwNa, MCHelpSwNal, MCHelpSwO, MCHelpSwOC, MCHelpSwOL, MCHelpSwOM, MCHelpSwOP,
            MCHelpSwOR, MCHelpSwOW, MCHelpSwP, MCHelpSwR, MCHelpSwRI, MCHelpSwSC, MCHelpSwSI, MCHelpSwSL,
            MCHelpSwTA, MCHelpSwTB, MCHelpSwTN, MCHelpSwTO, MCHelpSwTS, MCHelpSwU, MCHelpSwVUnr, MCHelpSwVER,
            MCHelpSwVP, MCHelpSwX, MCHelpSwXa, MCHelpSwXal, MCHelpSwY,
        ];
        let win32_only: &[&str] = &[
            MCHelpSwIEML, MCHelpSwVD, MCHelpSwAO, MCHelpSwOS, MCHelpSwIOFF, MCHelpSwEP2, MCHelpSwMLP, MCHelpSwOC,
            MCHelpSwONI, MCHelpSwDR, MCHelpSwRI,
        ];
        for &h in help {
            if !cfg!(windows) && win32_only.contains(&h) {
                continue;
            }
            if cfg!(unix) && h == MRARTitle2 {
                mprintf(MFwrSlTitle2);
                continue;
            }
            if !cfg!(windows) && (h == MCHelpSwOM || h == MCHelpSwAC) {
                continue;
            }
            mprintf(h);
        }
        mprintf("\n");
        errhnd::exit(exit_code)
    }

    pub fn add_arc_name(&mut self, name: &str) {
        self.arc_names.add_string(name);
    }

    pub fn get_arc_name(&mut self) -> Option<String> {
        self.arc_names.get_string()
    }
}

fn get_excl_attr(s: &str, exclude: bool, dir_mode: &mut DirFilterMode) -> u32 {
    let v = chars(s);
    if at(&v, 0).is_ascii_digit() {
        let t = s.trim();
        return if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
            u32::from_str_radix(h.trim_end_matches(|c: char| !c.is_ascii_hexdigit()), 16).unwrap_or(0)
        } else if t.len() > 1 && t.starts_with('0') {
            u32::from_str_radix(t.trim_end_matches(|c: char| !c.is_digit(8)), 8).unwrap_or(0)
        } else {
            atoiw(t) as u32
        };
    }
    let mut attr = 0;
    for (i, &c) in v.iter().enumerate() {
        match toupperw(c) {
            'D' => {
                *dir_mode = if exclude {
                    if at(&v, i + 1) == '1' {
                        DirFilterMode::ExcludeEmpty
                    } else {
                        DirFilterMode::ExcludeAll
                    }
                } else {
                    DirFilterMode::DirOnly
                }
            }
            'V' if cfg!(unix) => attr |= 0o020000,
            'R' if !cfg!(unix) => attr |= 1,
            'H' if !cfg!(unix) => attr |= 2,
            'S' if !cfg!(unix) => attr |= 4,
            'A' if !cfg!(unix) => attr |= 0x20,
            _ => {}
        }
    }
    attr
}

pub fn get_mod_size(s: &str, def_mult: u32) -> i64 {
    let v = chars(s);
    let mut size: i64 = 0;
    let mut floating_divider: i64 = 0;
    for &c in &v {
        if c.is_ascii_digit() {
            size = size * 10 + (c as i64 - '0' as i64);
            floating_divider *= 10;
        } else if c == '.' {
            floating_divider = 1;
        }
    }
    if !v.is_empty() {
        let mod_list = chars("bBkKmMgGtT");
        match mod_list.iter().position(|&m| m == *v.last().unwrap()) {
            None => size *= def_mult as i64,
            Some(m) => {
                let mut i = 2;
                while i <= m {
                    size *= if m & 1 != 0 { 1000 } else { 1024 };
                    i += 2;
                }
            }
        }
    }
    if floating_divider != 0 {
        size /= floating_divider;
    }
    size
}

/// Treat the list like rar;zip as *.rar;*.zip.
pub fn get_brief_mask_list(masks: &str, args: &mut StringList) {
    for part in masks.split(';') {
        let part = part.strip_prefix('.').unwrap_or(part);
        let mut mask = part.to_string();
        if !mask.contains(['*', '?', '.']) {
            mask.insert_str(0, "*.");
        }
        args.add_string(&mask);
    }
}

/// Read a text file with list of names or switches. For file lists
/// (`config` false) quotes are removed and "//" comments skipped.
pub fn read_text_file(name: &str, list: &mut StringList, config: bool, abort_on_error: bool) -> bool {
    let (unquote, skip_comments) = (!config, !config);
    let file_name = if config { get_config_name(name, true) } else { name.to_string() };
    let mut src = crate::file::File::new();
    if !file_name.is_empty() {
        let ok = if abort_on_error { src.w_open(&file_name) } else { src.open(&file_name, 0) };
        if !ok {
            if abort_on_error {
                errhnd::exit(RARX_OPEN);
            }
            return false;
        }
    } else {
        src.set_handle_std();
    }
    let mut data = Vec::new();
    let mut buf = vec![0u8; 4096];
    loop {
        let n = src.read(&mut buf);
        if n <= 0 {
            break;
        }
        data.extend_from_slice(&buf[..n as usize]);
    }
    let little = data.len() >= 2 && data[0] == 255 && data[1] == 254;
    let big = data.len() >= 2 && data[0] == 254 && data[1] == 255;
    let utf8_bom = data.len() >= 3 && data[0] == 0xef && data[1] == 0xbb && data[2] == 0xbf;
    let charset = detect_text_encoding(&data);
    let text: String = match charset {
        RarCharset::Unicode => {
            let (start, be) = if !little && !big { (0, false) } else { (2, big) };
            let end = data.len() & !1;
            let mut units = Vec::new();
            let mut i = start;
            while i < end {
                let u = if be { (data[i] as u16) << 8 | data[i + 1] as u16 } else { data[i] as u16 | (data[i + 1] as u16) << 8 };
                if u == 0 {
                    break;
                }
                units.push(u);
                i += 2;
            }
            String::from_utf16_lossy(&units)
        }
        RarCharset::Utf8 => crate::unicode::utf_to_wide(&data[if utf8_bom { 3 } else { 0 }..]),
        RarCharset::Oem => crate::unicode::oem_to_wide(&data),
        _ => crate::unicode::char_to_wide(&data),
    };
    let t = chars(&text);
    let mut cur = 0usize;
    while cur < t.len() && t[cur] != '\0' {
        let mut next = cur;
        let mut cmt: Option<usize> = None;
        while next < t.len() && t[next] != '\r' && t[next] != '\n' && t[next] != '\0' {
            if skip_comments && cmt.is_none() && t[next] == '/' && at(&t, next + 1) == '/' {
                cmt = Some(next);
            }
            next += 1;
        }
        let done = next >= t.len() || t[next] == '\0';
        let mut end = cmt.unwrap_or(next);
        while end > cur && (t[end - 1] == ' ' || t[end - 1] == '\t') {
            end -= 1;
        }
        let mut s = &t[cur..end];
        if unquote && s.first() == Some(&'"') && s.len() > 1 && s.last() == Some(&'"') {
            s = &s[1..s.len() - 1];
        } else if unquote && s.len() == 1 && s[0] == '"' {
            s = &s[..0];
        }
        if !s.is_empty() {
            list.add_string(&s.iter().collect::<String>());
        }
        if done {
            break;
        }
        cur = next + 1;
        while cur < t.len() && (t[cur] == '\r' || t[cur] == '\n') {
            cur += 1;
        }
    }
    true
}

fn is_text_utf8(src: &[u8]) -> bool {
    let mut i = 0;
    while i < src.len() {
        let c = src[i];
        i += 1;
        let high_one = c.leading_ones();
        if high_one == 1 || high_one > 6 {
            return false;
        }
        for _ in 1..high_one.max(1) {
            if i >= src.len() || src[i] & 0xc0 != 0x80 {
                return false;
            }
            i += 1;
        }
    }
    true
}

fn detect_text_encoding(data: &[u8]) -> RarCharset {
    if data.len() > 3 && data[0] == 0xef && data[1] == 0xbb && data[2] == 0xbf && is_text_utf8(&data[3..]) {
        return RarCharset::Utf8;
    }
    let little = data.len() > 2 && data[0] == 255 && data[1] == 254;
    let big = data.len() > 2 && data[0] == 254 && data[1] == 255;
    if little || big {
        let mut i = if little { 3 } else { 2 };
        while i < data.len() {
            if data[i] < 32 && data[i] != b'\r' && data[i] != b'\n' {
                return RarCharset::Unicode;
            }
            i += 2;
        }
    }
    RarCharset::Default
}
