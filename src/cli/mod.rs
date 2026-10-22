//! The binary's boundary: strict arguments and bounded, race-free input reading.

mod args;
mod input;

pub use args::{parse, USAGE};
pub use input::read;
