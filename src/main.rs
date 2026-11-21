// SPDX-License-Identifier: GPL-3.0-or-later

#![forbid(unsafe_code)]

fn main() {
    let args: Vec<String> = std::env::args_os().skip(1).map(|a| rarust::unicode::from_os(&a)).collect();
    let code = rarust::run(args);
    std::process::exit(code);
}
