// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors

//! Escape log control characters; never log provisioning input or helper output.

#[derive(Debug)]
pub enum Level {
    Error,
    Warning,
    Info,
}
pub fn emit(level: Level, args: std::fmt::Arguments<'_>) {
    let line = args.to_string();
    let escaped: String = line
        .chars()
        .take(4000)
        .flat_map(char::escape_debug)
        .collect();
    eprintln!("{level:?}: {escaped}");
}
#[macro_export]
macro_rules! error {($($t:tt)*)=>{$crate::log::emit($crate::log::Level::Error,format_args!($($t)*))};}
#[macro_export]
macro_rules! warning {($($t:tt)*)=>{$crate::log::emit($crate::log::Level::Warning,format_args!($($t)*))};}
#[macro_export]
macro_rules! info {($($t:tt)*)=>{$crate::log::emit($crate::log::Level::Info,format_args!($($t)*))};}
