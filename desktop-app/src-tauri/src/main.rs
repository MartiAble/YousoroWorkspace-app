#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if let Some(code) = yousoro_workspace::run_split_tun_helper() { std::process::exit(code); }
    yousoro_workspace::run();
}
