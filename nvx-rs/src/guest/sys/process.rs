//! Safe process, signal, inherited-descriptor, and standard-stream operations.

use std::ffi::{CStr, CString};
use std::io::{self, Write};
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};

use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, kill};
use nix::unistd::Pid;

use super::{Errno, FileDescriptor};
use crate::guest::parse::parse_decimal;

/// Whether this process inherited an ignored SIGPIPE across `exec`.
static SIGPIPE_IGNORED: AtomicBool = AtomicBool::new(false);

/// Runs before Rust's standard runtime changes SIGPIPE to `SIG_IGN`.
#[used]
#[unsafe(link_section = ".init_array")]
static CAPTURE_SIGPIPE: extern "C" fn() = capture_sigpipe;

/// Records the inherited SIGPIPE disposition before Rust startup, and leaves it in place.
extern "C" fn capture_sigpipe() {
    // SAFETY: `SIG_IGN` installs no handler. Setting it returns the previous disposition, which
    // the second call restores before another constructor runs.
    let Ok(inherited) = (unsafe { nix::sys::signal::signal(Signal::SIGPIPE, SigHandler::SigIgn) })
    else {
        return;
    };
    // SAFETY: `inherited` is the disposition that the preceding call returned.
    let _ = unsafe { nix::sys::signal::signal(Signal::SIGPIPE, inherited) };
    SIGPIPE_IGNORED.store(matches!(inherited, SigHandler::SigIgn), Ordering::Relaxed);
}

/// Restores the SIGPIPE disposition inherited across `exec`.
///
/// POSIX preserves `SIG_IGN` across `exec` and resets caught handlers to `SIG_DFL`. Rust's
/// standard runtime changes either state to `SIG_IGN` before `main`, so the constructor above
/// records the original first. The default disposition is restored unless the constructor saw an
/// ignored one, which preserves the historical behavior if a platform fails to run it.
pub(crate) fn restore_sigpipe() {
    let handler = if SIGPIPE_IGNORED.load(Ordering::Relaxed) {
        SigHandler::SigIgn
    } else {
        SigHandler::SigDfl
    };
    // SAFETY: neither `SIG_DFL` nor `SIG_IGN` installs a Rust callback.
    let _ = unsafe { nix::sys::signal::signal(Signal::SIGPIPE, handler) };
}

/// Ignores SIGINT and SIGHUP for the rest of the process, as `nvx-ingress`'s C program did before
/// it started announcing.
///
/// Like the C program, it ignores failures, which `signal` reports only for an invalid signal.
pub(crate) fn ignore_interrupt_and_hangup() {
    for signal in [Signal::SIGINT, Signal::SIGHUP] {
        // SAFETY: `SIG_IGN` installs no Rust callback.
        let _ = unsafe { nix::sys::signal::signal(signal, SigHandler::SigIgn) };
    }
}

/// Returns an owned, close-on-exec duplicate of the descriptor whose decimal number `text`
/// names, which this process inherited across `exec`, and makes that descriptor close-on-exec
/// too, so that the next `exec` closes it, as the C helper closed it before its own.
///
/// Duplicating the inherited descriptor, rather than adopting it, needs no proof that nothing
/// else in this process owns it: the duplicate is new, and only its flags change on the
/// original. A malformed number is `EINVAL`, and a closed descriptor `EBADF`.
pub(crate) fn take_inherited_descriptor(text: &CStr) -> Result<FileDescriptor, Errno> {
    let inherited = parse_decimal(text.to_bytes())
        .and_then(|value| RawFd::try_from(value).ok())
        .ok_or(Errno::EINVAL)?;
    // `nix`'s `fcntl` takes a borrowed descriptor, which must stay open while it is borrowed, so
    // these calls on an untrusted number go through libc.
    // SAFETY: `F_DUPFD_CLOEXEC` reads only the descriptor number, and fails with `EBADF` if it is
    // closed.
    let duplicate =
        Errno::result(unsafe { nix::libc::fcntl(inherited, nix::libc::F_DUPFD_CLOEXEC, 0) })?;
    // SAFETY: the kernel has just created `duplicate`, so it is open and nothing else owns it.
    let descriptor = unsafe { FileDescriptor::from_raw(duplicate) };
    // SAFETY: `F_SETFD` changes only the flags of the descriptor number.
    Errno::result(unsafe {
        nix::libc::fcntl(inherited, nix::libc::F_SETFD, nix::libc::FD_CLOEXEC)
    })?;
    Ok(descriptor)
}

/// One child process identifier returned by the safe fork/exec boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProcessId(Pid);

impl ProcessId {
    /// Wraps a positive process identifier returned by `fork` or `waitpid`.
    pub(super) fn from_pid(process: Pid) -> Self {
        Self(process)
    }

    /// Borrows the identifier of a child created by the standard test harness.
    #[cfg(test)]
    pub(crate) fn from_child(child: &std::process::Child) -> Self {
        Self(Pid::from_raw(child.id() as i32))
    }

    /// Returns the decimal process identifier followed by a newline.
    pub(crate) fn line(self) -> Vec<u8> {
        format!("{}\n", self.0.as_raw()).into_bytes()
    }
}

/// A terminal state observed while reaping a child.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChildStatus {
    /// The child called `_exit` or returned from its program.
    Exited(i32),
    /// A signal terminated the child.
    Signaled(i32),
    /// A wait state that is neither a normal exit nor signal termination.
    Other,
}

/// A child collected by a nonblocking reap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReapedChild {
    /// Identifier of the collected child.
    pub(crate) process: ProcessId,
    /// Terminal state reported by the kernel.
    pub(crate) status: ChildStatus,
}

/// Decodes Linux's raw wait status without narrowing real-time signal numbers.
fn child_status(process: nix::libc::pid_t, status: nix::libc::c_int) -> ReapedChild {
    let status = if nix::libc::WIFEXITED(status) {
        ChildStatus::Exited(nix::libc::WEXITSTATUS(status))
    } else if nix::libc::WIFSIGNALED(status) {
        ChildStatus::Signaled(nix::libc::WTERMSIG(status))
    } else {
        ChildStatus::Other
    };
    ReapedChild {
        process: ProcessId::from_pid(Pid::from_raw(process)),
        status,
    }
}

/// Reaps one available child without blocking.
///
/// libc is used instead of `nix` because `nix` converts a terminating signal to its finite
/// `Signal` enum and rejects Linux real-time signal numbers, after the child is reaped.
/// Interruptions are retried. `ECHILD`, a running child, and other errors all mean that no
/// reapable child is available, matching the C agent's best-effort orphan-reaping loop.
pub(crate) fn reap_any_nonblocking() -> Option<ReapedChild> {
    loop {
        let mut status = 0;
        // SAFETY: `status` is writable, `WNOHANG` never blocks, and a positive result names a
        // child that this call atomically reaped.
        let process = unsafe { nix::libc::waitpid(-1, &mut status, nix::libc::WNOHANG) };
        if process > 0 {
            return Some(child_status(process, status));
        }
        if process == 0 {
            return None;
        }
        if Errno::last() != Errno::EINTR {
            return None;
        }
    }
}

/// Waits for `process`, retrying interruptions.
///
/// libc is used for the same real-time signals as [`reap_any_nonblocking`].
pub(crate) fn wait(process: ProcessId) -> Option<ChildStatus> {
    loop {
        let mut status = 0;
        // SAFETY: `status` is writable and `process` came from this module's successful fork
        // boundary or a test-owned `Child`.
        let observed = unsafe { nix::libc::waitpid(process.0.as_raw(), &mut status, 0) };
        if observed == process.0.as_raw() {
            return Some(child_status(observed, status).status);
        }
        if observed < 0 && Errno::last() == Errno::EINTR {
            continue;
        }
        return None;
    }
}

/// Sends `SIGKILL` to the process group led by `process`.
pub(crate) fn kill_process_group(process: ProcessId) {
    let _ = kill(Pid::from_raw(-process.0.as_raw()), Signal::SIGKILL);
}

/// Returns whether `process` has reached a waitable terminal state without reaping it.
///
/// libc is used because `nix`'s `waitid` decodes the state into a `WaitStatus` too, which fails
/// for a real-time signal, whereas only the child that `si_pid` names matters here.
pub(crate) fn has_exited(process: ProcessId) -> Result<bool, Errno> {
    // SAFETY: zero is a valid initial representation for `siginfo_t`.
    let mut information = unsafe { std::mem::zeroed::<nix::libc::siginfo_t>() };
    // SAFETY: `information` is writable; `WNOWAIT` leaves the child available to the owner.
    Errno::result(unsafe {
        nix::libc::waitid(
            nix::libc::P_PID,
            process.0.as_raw() as nix::libc::id_t,
            &mut information,
            nix::libc::WEXITED | nix::libc::WNOHANG | nix::libc::WNOWAIT,
        )
    })?;
    // SAFETY: successful `waitid` initialized the Linux `siginfo_t` child-event union.
    Ok(unsafe { information.si_pid() } == process.0.as_raw())
}

/// Replaces the process image with `path` and `arguments`, and with `environment`, or without
/// one, the current environment. It returns only the error of a failed `exec`.
pub(crate) fn exec(path: &CStr, arguments: &[CString], environment: Option<&[CString]>) -> Errno {
    let result = match environment {
        Some(environment) => nix::unistd::execve(path, arguments, environment),
        None => nix::unistd::execv(path, arguments),
    };
    match result {
        Ok(never) => match never {},
        Err(error) => error,
    }
}

/// Writes all bytes to standard error and ignores failures.
pub(crate) fn write_standard_error(bytes: &[u8]) {
    let mut remaining = bytes;
    while !remaining.is_empty() {
        match nix::unistd::write(io::stderr(), remaining) {
            Ok(0) => return,
            Ok(count) => remaining = &remaining[count..],
            Err(Errno::EINTR) => {}
            Err(_) => return,
        }
    }
}

/// RAII owner of a temporarily replaced SIGPIPE disposition.
struct SigpipeGuard {
    /// Exact action that must be restored.
    previous: SigAction,
    /// Whether Drop still owns the restoration.
    active: bool,
}

impl SigpipeGuard {
    /// Installs `SIG_IGN` and records the prior action.
    fn ignore() -> Result<Self, Errno> {
        let ignored = SigAction::new(SigHandler::SigIgn, SaFlags::empty(), SigSet::empty());
        // SAFETY: `SIG_IGN` installs no Rust callback.
        let previous = unsafe { nix::sys::signal::sigaction(Signal::SIGPIPE, &ignored) }?;
        Ok(Self {
            previous,
            active: true,
        })
    }

    /// Explicitly restores the prior action and reports a failure.
    fn restore(mut self) -> Result<(), Errno> {
        self.active = false;
        // SAFETY: `previous` is the exact action that the installation replaced.
        unsafe { nix::sys::signal::sigaction(Signal::SIGPIPE, &self.previous) }.map(|_| ())
    }
}

impl Drop for SigpipeGuard {
    /// Best-effort restoration for unwinding test paths.
    fn drop(&mut self) {
        if self.active {
            // SAFETY: this guard owns the exact action that the installation replaced.
            let _ = unsafe { nix::sys::signal::sigaction(Signal::SIGPIPE, &self.previous) };
        }
    }
}

/// Runs `operation` while `SIGPIPE` is ignored, then restores the exact prior disposition.
///
/// The managed agent is single-threaded at this call site, so the process-wide disposition
/// cannot race another thread. Explicit restoration reports errors; RAII also restores it if a
/// host test unwinds through the operation.
pub(crate) fn with_sigpipe_ignored(
    operation: impl FnOnce() -> Result<(), Errno>,
) -> Result<(), Errno> {
    let guard = SigpipeGuard::ignore()?;
    let result = operation();
    guard.restore()?;
    result
}

/// Returns the current SIGPIPE handler token, flags, and mask for regression tests.
///
/// A whole `SigAction` does not compare reliably: libc copies only the kernel's part of the mask.
#[cfg(test)]
pub(crate) fn sigpipe_disposition() -> Result<(usize, SaFlags, SigSet), Errno> {
    let probe = SigAction::new(SigHandler::SigIgn, SaFlags::empty(), SigSet::empty());
    // SAFETY: the probe installs no Rust callback, and the second call reinstalls the action
    // that the first one replaced.
    let current = unsafe { nix::sys::signal::sigaction(Signal::SIGPIPE, &probe) }?;
    // SAFETY: `current` is the exact action that the probe replaced.
    unsafe { nix::sys::signal::sigaction(Signal::SIGPIPE, &current) }?;
    let handler = nix::libc::sigaction::from(current).sa_sigaction;
    Ok((handler, current.flags(), current.mask()))
}

/// Writes `message` to a diagnostic I/O port through a descriptor.
///
/// A write that stores no byte is `EIO`, the status that the agent reports for it.
pub(crate) fn write_port_diagnostic(
    descriptor: &FileDescriptor,
    message: &[u8],
) -> Result<(), Errno> {
    for byte in message {
        if descriptor.pwrite(std::slice::from_ref(byte), 0xe9)? != 1 {
            return Err(Errno::EIO);
        }
    }
    Ok(())
}

/// Standard output with the error behavior of C stdio.
///
/// C line-buffers a terminal, so a failed terminal write fails `printf`. It fully buffers other
/// destinations until `exit`, whose flush failure these tools ignored. This adapter performs the
/// write immediately but suppresses the same nonterminal errors; interrupted writes remain
/// visible so `Write::write_all` retries them.
pub(crate) struct Stdout {
    /// Whether C stdio would line-buffer standard output.
    terminal: bool,
}

impl Stdout {
    /// Returns an adapter for the process's standard output.
    pub(crate) fn new() -> Self {
        let stdout = io::stdout();
        let terminal = nix::unistd::isatty(&stdout).unwrap_or(false);
        Self { terminal }
    }
}

impl Write for Stdout {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let stdout = io::stdout();
        match nix::unistd::write(&stdout, bytes) {
            Ok(count) => Ok(count),
            Err(error) if self.terminal || error == nix::errno::Errno::EINTR => {
                Err(io::Error::from(error))
            }
            Err(_) => Ok(bytes.len()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Standard output written with direct `write` calls, whose every failure is reported.
///
/// `nvx-device-io`'s C program wrote its result with its own `write` loop rather than stdio. The
/// loop retried only `EINTR`, and failed on any other error or on a write that wrote nothing.
/// [`Write::write_all`] over this adapter does the same.
pub(crate) struct DirectStdout;

impl Write for DirectStdout {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        nix::unistd::write(io::stdout(), bytes).map_err(io::Error::from)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, Write};
    use std::os::fd::{AsFd, AsRawFd};

    use nix::fcntl::{FcntlArg, FdFlag, fcntl};

    use super::*;

    /// Returns whether `descriptor` is close-on-exec.
    fn closes_on_exec(descriptor: impl AsFd) -> bool {
        let flags = fcntl(descriptor, FcntlArg::F_GETFD).unwrap();
        FdFlag::from_bits_retain(flags).contains(FdFlag::FD_CLOEXEC)
    }

    #[test]
    fn an_inherited_descriptor_is_duplicated_and_closes_on_exec() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"config").unwrap();
        file.rewind().unwrap();
        fcntl(file.as_fd(), FcntlArg::F_SETFD(FdFlag::empty())).unwrap();
        let argument = CString::new(file.as_raw_fd().to_string()).unwrap();
        let duplicate = take_inherited_descriptor(&argument).unwrap();
        assert_ne!(duplicate.argument(), argument);
        assert!(closes_on_exec(duplicate.borrowed()));
        assert!(closes_on_exec(&file));
        let mut bytes = [0u8; 8];
        assert_eq!(duplicate.read(&mut bytes), Ok(6));
        assert_eq!(&bytes[..6], b"config");
        assert_eq!(duplicate.close(), Ok(()));
    }

    #[test]
    fn an_inherited_descriptor_number_is_decimal_and_open() {
        for text in [c"", c"+7", c" 42", c"-1", c"1x", c"2147483648"] {
            assert_eq!(
                take_inherited_descriptor(text).unwrap_err(),
                Errno::EINVAL,
                "{text:?}"
            );
        }
        assert_eq!(
            take_inherited_descriptor(c"2147483647").unwrap_err(),
            Errno::EBADF
        );
    }
}
