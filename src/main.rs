#![doc = include_str!("../README.md")]
// Clippy lints
#![warn(clippy::large_stack_arrays)]
#![warn(clippy::arithmetic_side_effects)]
#![warn(clippy::unwrap_used)]
#![warn(clippy::indexing_slicing)]
#![warn(clippy::panic)]
#![warn(clippy::todo)]
#![warn(clippy::unimplemented)]
#![warn(clippy::unreachable)]
#![warn(clippy::missing_panics_doc)]
#![warn(clippy::allow_attributes_without_reason)]
#![warn(clippy::cognitive_complexity)]

use std::process;
use wgproxy::config::Config;

pub fn main() {
    // Load config and enter app runloop
    let Err(e) = Config::from_env().and_then(wgproxy::eventloop);
    wgproxy::log!(fatal: e);

    // Exit with error status
    process::exit(1);
}
