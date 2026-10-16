//! Safe path, mount, ownership, mode, and working-directory operations.

use std::ffi::{CStr, CString};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub(crate) use nix::mount::MsFlags as MountFlags;
use nix::sys::stat::{FchmodatFlags, Mode};
use nix::unistd::{Gid, Uid};

use super::Errno;

/// Converts a Unix path to a NUL-terminated string, or `EINVAL` if it contains a NUL.
pub(crate) fn path_c_string(path: &Path) -> Result<CString, Errno> {
    super::c_string(path.as_os_str().as_bytes())
}

/// Mounts `source` on `target` with no data argument.
pub(crate) fn mount(
    source: Option<&CStr>,
    target: &CStr,
    filesystem: Option<&CStr>,
    flags: MountFlags,
) -> Result<(), Errno> {
    nix::mount::mount(source, target, filesystem, flags, None::<&CStr>)
}

/// Changes the owner and group of `path`, following the final symlink like C `chown`.
pub(crate) fn chown(path: &CStr, uid: u32, gid: u32) -> Result<(), Errno> {
    nix::unistd::chown(path, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))
}

/// Changes the permission bits of `path`, following the final symlink like C `chmod`.
///
/// `fchmodat` relative to the working directory, without `AT_SYMLINK_NOFOLLOW`, is the system
/// call that `chmod` makes.
pub(crate) fn chmod(path: &CStr, mode: Mode) -> Result<(), Errno> {
    nix::sys::stat::fchmodat(
        nix::fcntl::AT_FDCWD,
        path,
        mode,
        FchmodatFlags::FollowSymlink,
    )
}

/// Changes the process working directory to `path`.
pub(crate) fn change_directory(path: &CStr) -> Result<(), Errno> {
    nix::unistd::chdir(path)
}

/// Returns the physical working directory, or `ERANGE` if it needs `maximum` bytes or more.
///
/// `libc`'s `getcwd` writes into a fixed buffer, which preserves the C agent's `ERANGE`, whereas
/// `nix` and the standard library grow their storage until the path fits.
pub(crate) fn current_directory(maximum: usize) -> Result<Vec<u8>, Errno> {
    let mut bytes = vec![0u8; maximum];
    // SAFETY: the vector supplies `maximum` writable bytes, and libc NUL-terminates the path on
    // success.
    let result = unsafe { nix::libc::getcwd(bytes.as_mut_ptr().cast(), bytes.len()) };
    if result.is_null() {
        return Err(Errno::last());
    }
    let length = bytes
        .iter()
        .position(|&byte| byte == 0)
        .ok_or(Errno::ERANGE)?;
    bytes.truncate(length);
    Ok(bytes)
}
