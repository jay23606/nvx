//! The programs that run in NVX's Linux guests, which ship as `/sbin/nvx-*`.
//!
//! Each module holds one program, and the crate's binary of the same name runs its `main`. The
//! programs keep the command lines, exit statuses, and output of the C programs that they
//! replace, except that numeric arguments are plain decimal, or `0x`-prefixed hexadecimal where
//! the C program also read hexadecimal, error messages describe `errno` values with `nix`'s
//! text, and `nvx-ingress` reads the kernel's socket tables and sysctl, and its test snapshots,
//! only in the form in which the kernel writes them, rejecting the signed, prefixed, and other
//! lenient forms that C's `strtoul` and `scanf` also read.
//!
//! # Conventions
//!
//! - Program modules deny unsafe code. Only the private `sys` module may use it, behind
//!   documented safe operations. It makes every system call through `nix`, with the enabled,
//!   default-free feature set, except the few managed-agent operations that `nix` cannot
//!   provide, which `sys` documents, and the programs take random bytes from the `getrandom`
//!   crate.
//! - Descriptors and mappings have owners that release them when dropped. Where a C program
//!   reported a cleanup failure, a consuming `close` or `unmap` returns it instead. Raw
//!   descriptor integers never leave `sys`, and no resource is dropped by hand: where a C
//!   program released one before a later step, its scope ends there, for example in a helper
//!   function that returns what the later step needs.
//! - A descriptor stays with the library that opened it: one that `sys` opens through `nix` is
//!   read and written only through `sys`, and one that the standard library opens only through
//!   it, except that a test may hand one to `FileDescriptor::from_owned`, which takes it over
//!   whole. No descriptor thus has two owners or two buffers; a standard-library adapter such as
//!   `BufReader` may add the one buffer of a `sys` descriptor through the `std::io::Read` that
//!   `FileDescriptor` implements. `sys::Stdout` and `sys::DirectStdout` write standard output
//!   directly, past the standard library's line buffer, so the programs never print with the
//!   standard library's macros: `print!` would reorder its buffered output with theirs, and
//!   `eprint!` would bypass the error streams that the programs' tests capture. Clippy denies
//!   both here.
//! - Every program fails with the shared `CommandError`, whose kind selects the program's exit
//!   status from the shared `ExitStatus`. Every module, type, field, variant, constant, static,
//!   and function is documented, which CI enforces with `clippy::missing_docs_in_private_items`.
//! - The programs use `nix`, `getrandom`, or the standard library rather than reimplement a
//!   facility, and keep a parser of their own only for forms that no library parses.
#![deny(unsafe_code)]
#![deny(clippy::print_stdout, clippy::print_stderr)]

mod parse;
mod status;
#[allow(unsafe_code)]
mod sys;

pub mod console_pending;
#[cfg(target_arch = "x86_64")]
pub mod device_io;
#[cfg(target_arch = "x86_64")]
pub mod exit;
pub mod ingress;
pub mod managed_agent;
#[cfg(target_arch = "x86_64")]
pub mod mmio_write;
pub mod reseed;
