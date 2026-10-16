use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::guest::sys::{self, Errno, Mode, MountFlags, OpenFlags, c_string};
use crate::protocol::{self, GuestHostMap};

use super::seam::{System, path_c_string};

/// Progress and latched failure state of the boot-announced host mapping table.
#[derive(Default)]
pub(crate) struct HostMappings {
    /// Number of mappings announced on the kernel command line.
    pub(crate) expected: u32,
    /// Number of mappings mounted in order.
    pub(crate) applied: u32,
    /// Whether a prior mount failure permanently refused the remaining table.
    pub(crate) failed: bool,
}

/// Failure returned while validating or applying one MAPS request.
#[derive(Debug)]
pub(crate) enum MappingError {
    /// The payload or sequence does not match the announced table.
    Invalid,
    /// A specific mapping failed while being mounted.
    Mount {
        /// Errno returned by mount preparation or the mount itself.
        status: i32,
        /// Zero-based mapping-table entry that failed.
        entry: u32,
    },
}

/// Reads the announced mapping count and validates the host export mount.
pub(crate) fn prepare(system: &mut impl System, mappings: &mut HostMappings) -> Result<(), Errno> {
    let mut command_line = [0u8; 4096];
    let count = std::fs::File::open(&system.paths().proc_cmdline)
        .and_then(|mut file| file.read(&mut command_line[..4095]))
        .map_err(|error| sys::errno_of(&error))?;
    mappings.expected =
        protocol::parse_host_mapping_count(&command_line[..count]).map_err(|_| Errno::EINVAL)?;
    let hostfs = system.paths().hostfs_dir.clone();
    let root = hostfs.join("root");
    let mounted = match (std::fs::metadata(&hostfs), std::fs::metadata(&root)) {
        (Ok(parent), Ok(export)) => parent.dev() != export.dev(),
        _ => false,
    };
    if mounted {
        let hostfs = path_c_string(&hostfs)?;
        system.chown(&hostfs, 0, 0)?;
        system.chmod(&hostfs, Mode::from_bits_retain(0o700))?;
    }
    if mappings.expected != 0 && !mounted {
        return Err(Errno::ENOENT);
    }
    Ok(())
}

/// Validates and applies one ordered batch of host mappings.
pub(crate) fn apply_request(
    system: &mut impl System,
    mappings: &mut HostMappings,
    payload: &[u8],
) -> Result<(), MappingError> {
    if mappings.failed {
        return Err(MappingError::Invalid);
    }
    let request =
        protocol::decode_guest_maps_payload(payload).map_err(|_| MappingError::Invalid)?;
    let count = u32::try_from(request.maps.len()).map_err(|_| MappingError::Invalid)?;
    if request.first != mappings.applied
        || count == 0
        || mappings.applied > mappings.expected
        || count > mappings.expected - mappings.applied
    {
        return Err(MappingError::Invalid);
    }
    for (offset, mapping) in request.maps.iter().enumerate() {
        if let Err(error) = apply(system, mapping) {
            mappings.failed = true;
            return Err(MappingError::Mount {
                status: error as i32,
                entry: request.first + offset as u32,
            });
        }
        mappings.applied += 1;
    }
    Ok(())
}

/// Creates one target and bind-mounts a validated mapping onto it.
fn apply(system: &mut impl System, mapping: &GuestHostMap) -> Result<(), Errno> {
    let root = system.paths().hostfs_dir.join("root");
    let source = append_bytes(&root, &mapping.source);
    let target = PathBuf::from(std::ffi::OsStr::from_bytes(&mapping.target));
    let metadata = std::fs::symlink_metadata(&source).map_err(|error| sys::errno_of(&error))?;
    if metadata.file_type().is_dir() {
        make_directories(&target, true)?;
    } else if metadata.file_type().is_file() {
        make_directories(&target, false)?;
        match std::fs::symlink_metadata(&target) {
            Ok(existing) if existing.file_type().is_file() => {}
            Ok(_) => return Err(Errno::EINVAL),
            Err(error) => match sys::errno_of(&error) {
                Errno::ENOENT => create_file(&target)?,
                error => return Err(error),
            },
        }
    } else {
        return Err(Errno::EINVAL);
    }
    let source = path_c_string(&source)?;
    let target = path_c_string(&target)?;
    system.mount(Some(&source), &target, None, MountFlags::MS_BIND)?;
    let mut flags =
        MountFlags::MS_BIND | MountFlags::MS_REMOUNT | MountFlags::MS_NOSUID | MountFlags::MS_NODEV;
    if mapping.read_only {
        flags |= MountFlags::MS_RDONLY;
    }
    system.mount(None, &target, None, flags)
}

/// Appends arbitrary Unix bytes to a trusted root path.
fn append_bytes(root: &Path, suffix: &[u8]) -> PathBuf {
    let mut bytes = root.as_os_str().as_bytes().to_vec();
    bytes.push(b'/');
    bytes.extend_from_slice(suffix);
    PathBuf::from(std::ffi::OsStr::from_bytes(&bytes))
}

/// Creates every missing directory component in `path`.
fn make_directories(path: &Path, include_last: bool) -> Result<(), Errno> {
    let bytes = path.as_os_str().as_bytes();
    for index in 1..=bytes.len() {
        if bytes.get(index) == Some(&b'/') || (index == bytes.len() && include_last) {
            let directory = c_string(&bytes[..index])?;
            match sys::create_directory(&directory, Mode::from_bits_retain(0o755)) {
                Ok(()) | Err(Errno::EEXIST) => {}
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

/// Atomically creates one regular mapping target without following a symlink.
///
/// As in the C agent, the new file closes at once, and a close failure is ignored.
fn create_file(path: &Path) -> Result<(), Errno> {
    let path = path_c_string(path)?;
    sys::open(
        &path,
        OpenFlags::O_RDONLY
            | OpenFlags::O_CREAT
            | OpenFlags::O_EXCL
            | OpenFlags::O_CLOEXEC
            | OpenFlags::O_NOFOLLOW,
        Mode::from_bits_retain(0o644),
    )
    .map(|_created| ())
}

#[cfg(test)]
mod tests {
    use std::os::unix::ffi::OsStrExt;

    use super::super::seam::{Paths, TestSystem};
    use super::*;

    fn setup(expected: u32) -> (tempfile::TempDir, TestSystem, HostMappings) {
        let temporary = tempfile::tempdir().unwrap();
        let hostfs = temporary.path().join("hostfs");
        std::fs::create_dir_all(hostfs.join("root/0/src")).unwrap();
        std::fs::write(hostfs.join("root/0/notes.txt"), b"notes").unwrap();
        std::fs::create_dir(hostfs.join("root/1")).unwrap();
        let paths = Paths {
            hostfs_dir: hostfs,
            ..Paths::default()
        };
        (
            temporary,
            TestSystem::new(paths),
            HostMappings {
                expected,
                ..HostMappings::default()
            },
        )
    }

    fn payload(first: u32, entries: &[(&[u8], &[u8], u16)], count: Option<u32>) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&first.to_le_bytes());
        payload.extend_from_slice(&count.unwrap_or(entries.len() as u32).to_le_bytes());
        for (source, target, flags) in entries {
            payload.extend_from_slice(&flags.to_le_bytes());
            payload.extend_from_slice(&(source.len() as u16).to_le_bytes());
            payload.extend_from_slice(&(target.len() as u16).to_le_bytes());
            payload.extend_from_slice(source);
            payload.extend_from_slice(target);
        }
        payload
    }

    #[test]
    fn mappings_mount_in_order_and_unblock_workloads() {
        let (temporary, mut system, mut mappings) = setup(3);
        let guest = temporary.path().join("guest");
        let source = guest.join("src");
        let notes = guest.join("src/notes.txt");
        let out = guest.join("out");
        let first = payload(
            0,
            &[
                (
                    b"0/src",
                    source.as_os_str().as_bytes(),
                    protocol::MAP_READ_ONLY,
                ),
                (b"0/notes.txt", notes.as_os_str().as_bytes(), 0),
            ],
            None,
        );
        apply_request(&mut system, &mut mappings, &first).unwrap();
        assert_eq!((mappings.applied, mappings.expected), (2, 3));
        let second = payload(2, &[(b"1", out.as_os_str().as_bytes(), 0)], None);
        apply_request(&mut system, &mut mappings, &second).unwrap();
        assert_eq!((mappings.applied, mappings.expected), (3, 3));
        assert_eq!(system.mounts.len(), 6);
        assert_eq!(
            system.mounts[1].2,
            MountFlags::MS_BIND
                | MountFlags::MS_REMOUNT
                | MountFlags::MS_NOSUID
                | MountFlags::MS_NODEV
                | MountFlags::MS_RDONLY
        );
        assert!(source.is_dir());
        assert!(notes.is_file());
        assert!(out.is_dir());
    }

    #[test]
    fn entries_beyond_the_announcement_or_out_of_order_are_refused() {
        let (temporary, mut system, mut mappings) = setup(1);
        let target = temporary.path().join("guest/src");
        let entry = [(b"0/src".as_slice(), target.as_os_str().as_bytes(), 0)];
        for invalid in [payload(1, &entry, None), payload(0, &entry, Some(2))] {
            assert!(matches!(
                apply_request(&mut system, &mut mappings, &invalid),
                Err(MappingError::Invalid)
            ));
        }
        apply_request(&mut system, &mut mappings, &payload(0, &entry, None)).unwrap();
        assert!(matches!(
            apply_request(&mut system, &mut mappings, &payload(1, &entry, None)),
            Err(MappingError::Invalid)
        ));
        assert_eq!(system.mounts.len(), 2);
    }

    #[test]
    fn malformed_tables_mount_nothing() {
        let (temporary, mut system, mut mappings) = setup(2);
        let target = temporary.path().join("guest/x");
        let good = (b"0/src".as_slice(), target.as_os_str().as_bytes(), 0);
        let malformed = [
            payload(
                0,
                &[good, (b"0/../1", target.as_os_str().as_bytes(), 0)],
                None,
            ),
            payload(
                0,
                &[good, (b"/0/src", target.as_os_str().as_bytes(), 0)],
                None,
            ),
            payload(0, &[good, (b"0/src", b"relative", 0)], None),
            payload(0, &[good, (b".", target.as_os_str().as_bytes(), 0)], None),
            payload(
                0,
                &[good, (b"0//src", target.as_os_str().as_bytes(), 0)],
                None,
            ),
            payload(
                0,
                &[good, (b"0/src", target.as_os_str().as_bytes(), 2)],
                None,
            ),
            payload(0, &[], Some(0)),
            vec![0, 0, 0],
        ];
        for payload in malformed {
            assert!(matches!(
                apply_request(&mut system, &mut mappings, &payload),
                Err(MappingError::Invalid)
            ));
        }
        assert!(system.mounts.is_empty());
        assert_eq!(mappings.applied, 0);
    }

    #[test]
    fn without_an_announcement_tables_are_refused() {
        let (temporary, mut system, mut mappings) = setup(0);
        let target = temporary.path().join("guest/src");
        let request = payload(0, &[(b"0/src", target.as_os_str().as_bytes(), 0)], None);
        assert!(matches!(
            apply_request(&mut system, &mut mappings, &request),
            Err(MappingError::Invalid)
        ));
        assert!(system.mounts.is_empty());
    }

    #[test]
    fn a_failed_mount_latches_and_keeps_refusing_tables() {
        let (temporary, mut system, mut mappings) = setup(2);
        system.fail_mount_call = Some(1);
        let target = temporary.path().join("guest/src");
        let request = payload(0, &[(b"0/src", target.as_os_str().as_bytes(), 0)], None);
        assert!(matches!(
            apply_request(&mut system, &mut mappings, &request),
            Err(MappingError::Mount { status, entry: 0 }) if status == Errno::ENOENT as i32
        ));
        assert!(mappings.failed);
        assert!(matches!(
            apply_request(&mut system, &mut mappings, &request),
            Err(MappingError::Invalid)
        ));
        assert_eq!(mappings.applied, 0);
    }
}
