use std::path::Path;
use std::time::Duration;

use crate::guest::sys::{self, ChildStatus, Errno, Mode, MountFlags, OpenFlags, ProcessId};

use super::seam::{System, path_c_string};

/// Number of ten-millisecond retries after killing a cgroup.
const SETTLE_ATTEMPTS: usize = 200;
/// Delay between cgroup-emptiness checks.
const SETTLE_DELAY: Duration = Duration::from_millis(10);

/// Mounts cgroup v2 when needed and prepares the per-execution cgroup.
pub(crate) fn prepare(system: &mut impl System) -> Result<(), Errno> {
    let root = system.paths().cgroup_root.clone();
    if std::fs::metadata(root.join("cgroup.procs")).is_err() {
        mkdir(&root)?;
        let target = path_c_string(&root)?;
        system.mount(
            Some(c"cgroup2"),
            &target,
            Some(c"cgroup2"),
            MountFlags::MS_NOSUID | MountFlags::MS_NODEV | MountFlags::MS_NOEXEC,
        )?;
    }
    let execution = root.join("nvx-exec");
    mkdir(&execution)?;
    match std::fs::metadata(execution.join("pids.current")) {
        Ok(_) => Ok(()),
        Err(error) => match sys::errno_of(&error) {
            Errno::ENOENT => write_path(&root.join("cgroup.subtree_control"), b"+pids"),
            error => Err(error),
        },
    }
}

/// Returns whether the execution cgroup reports one or more tasks.
pub(crate) fn has_tasks(system: &impl System) -> Result<bool, Errno> {
    let path = system
        .paths()
        .cgroup_root
        .join("nvx-exec")
        .join("pids.current");
    let path = path_c_string(&path)?;
    let descriptor = sys::open(
        &path,
        OpenFlags::O_RDONLY | OpenFlags::O_CLOEXEC,
        Mode::empty(),
    )?;
    let mut buffer = [0u8; 32];
    let mut length = 0;
    let result = loop {
        match descriptor.read(&mut buffer[length..]) {
            Ok(count) if count > 0 => {
                length += count;
                if length < buffer.len() {
                    continue;
                }
                break Err(Errno::EOVERFLOW);
            }
            Ok(_) => break parse_count(&buffer[..length]),
            Err(Errno::EINTR) => {}
            Err(error) => break Err(error),
        }
    };
    match result {
        Ok(value) => descriptor.close().map(|()| value),
        Err(error) => Err(error),
    }
}

/// Parses the canonical decimal form of `pids.current`.
fn parse_count(bytes: &[u8]) -> Result<bool, Errno> {
    if bytes.len() < 2
        || bytes.last() != Some(&b'\n')
        || (bytes.first() == Some(&b'0') && bytes.len() != 2)
        || !bytes[..bytes.len() - 1].iter().all(u8::is_ascii_digit)
    {
        return Err(Errno::EPROTO);
    }
    Ok(bytes.first() != Some(&b'0'))
}

/// Requests atomic killing of every process in the execution cgroup.
pub(crate) fn kill(system: &mut impl System) -> Result<(), Errno> {
    let path = system
        .paths()
        .cgroup_root
        .join("nvx-exec")
        .join("cgroup.kill");
    let result = write_path(&path, b"1");
    if let Err(error) = result {
        super::diagnostics::error(system, "exec-cgroup-kill", error as i32);
    }
    result
}

/// Reaps every currently available child and records the workload's first terminal state.
pub(crate) fn reap(child: ProcessId, status: &mut Option<ChildStatus>) {
    while let Some(observed) = sys::reap_any_nonblocking() {
        if observed.process == child && status.is_none() {
            *status = Some(observed.status);
        }
    }
}

/// Reaps orphaned descendants and returns the cgroup's current occupancy.
pub(crate) fn verify_empty(system: &impl System) -> Result<bool, Errno> {
    while sys::reap_any_nonblocking().is_some() {}
    has_tasks(system)
}

/// Kills and reaps the execution cgroup until it is empty or the deadline expires.
pub(crate) fn settle(system: &mut impl System) -> Result<(), Errno> {
    kill(system)?;
    for attempt in 0..=SETTLE_ATTEMPTS {
        if !verify_empty(system)? {
            return Ok(());
        }
        if attempt != SETTLE_ATTEMPTS {
            std::thread::sleep(SETTLE_DELAY);
        }
    }
    Err(Errno::ETIMEDOUT)
}

/// Kills the workload process group and, in direct mode, its cgroup.
pub(crate) fn terminate(system: &mut impl System, direct: bool, child: ProcessId) {
    sys::kill_process_group(child);
    if direct {
        let _ = kill(system);
    }
}

/// Moves a sandbox launcher into the container cgroup.
pub(crate) fn write_container_pid(system: &impl System, child: ProcessId) -> Result<(), Errno> {
    write_path(&system.paths().container_cgroup_procs, &child.line())
}

/// Creates one cgroup directory with mode 0755, accepting an existing path.
fn mkdir(path: &Path) -> Result<(), Errno> {
    let path = path_c_string(path)?;
    match sys::create_directory(&path, Mode::from_bits_retain(0o755)) {
        Ok(()) | Err(Errno::EEXIST) => Ok(()),
        Err(error) => Err(error),
    }
}

/// Writes a complete control value and reports explicit close failure.
fn write_path(path: &Path, bytes: &[u8]) -> Result<(), Errno> {
    let path = path_c_string(path)?;
    let descriptor = sys::open(
        &path,
        OpenFlags::O_WRONLY | OpenFlags::O_CLOEXEC,
        Mode::empty(),
    )?;
    descriptor.write_all(bytes)?;
    descriptor.close()
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::super::seam::{Paths, TestSystem};
    use super::*;

    fn setup() -> (tempfile::TempDir, TestSystem) {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("cgroup");
        let execution = root.join("nvx-exec");
        std::fs::create_dir_all(&execution).unwrap();
        std::fs::write(root.join("cgroup.procs"), b"").unwrap();
        std::fs::write(root.join("cgroup.subtree_control"), b"").unwrap();
        std::fs::write(execution.join("pids.current"), b"0\n").unwrap();
        std::fs::write(execution.join("cgroup.kill"), b"").unwrap();
        std::fs::write(execution.join("cgroup.procs"), b"").unwrap();
        let paths = Paths {
            cgroup_root: root,
            ..Paths::default()
        };
        (temporary, TestSystem::new(paths))
    }

    #[test]
    fn task_count_requires_a_canonical_decimal() {
        let _process = super::super::PROCESS_TEST_LOCK.lock().unwrap();
        let (_temporary, system) = setup();
        let tasks = system.paths.cgroup_root.join("nvx-exec/pids.current");
        for (contents, expected) in [
            (b"0\n".as_slice(), false),
            (b"1\n", true),
            (b"10\n", true),
            (b"4194304\n", true),
        ] {
            std::fs::write(&tasks, contents).unwrap();
            assert_eq!(has_tasks(&system).unwrap(), expected, "{contents:?}");
        }
        for contents in [
            b"".as_slice(),
            b"\n",
            b"0",
            b"00\n",
            b"01\n",
            b"-1\n",
            b"+1\n",
            b" 1\n",
            b"1 \n",
            b"0\n0\n",
            b"1\0\n",
            b"max\n",
        ] {
            std::fs::write(&tasks, contents).unwrap();
            assert_eq!(
                has_tasks(&system).unwrap_err(),
                Errno::EPROTO,
                "{contents:?}"
            );
        }
        std::fs::write(&tasks, [b'1'; 40]).unwrap();
        assert_eq!(has_tasks(&system).unwrap_err(), Errno::EOVERFLOW);
    }

    #[test]
    fn missing_and_unreadable_task_counts_are_errors() {
        let _process = super::super::PROCESS_TEST_LOCK.lock().unwrap();
        let (_temporary, system) = setup();
        let tasks = system.paths.cgroup_root.join("nvx-exec/pids.current");
        std::fs::remove_file(&tasks).unwrap();
        assert_eq!(has_tasks(&system).unwrap_err(), Errno::ENOENT);
        std::fs::create_dir(&tasks).unwrap();
        assert!(has_tasks(&system).is_err());
    }

    #[test]
    fn preparation_enables_the_pids_controller_once() {
        let _process = super::super::PROCESS_TEST_LOCK.lock().unwrap();
        let (_temporary, mut system) = setup();
        let root = system.paths.cgroup_root.clone();
        prepare(&mut system).unwrap();
        assert_eq!(
            std::fs::read(root.join("cgroup.subtree_control")).unwrap(),
            b""
        );
        std::fs::remove_file(root.join("nvx-exec/pids.current")).unwrap();
        prepare(&mut system).unwrap();
        assert_eq!(
            std::fs::read(root.join("cgroup.subtree_control")).unwrap(),
            b"+pids"
        );
        std::fs::remove_file(root.join("cgroup.subtree_control")).unwrap();
        assert_eq!(prepare(&mut system).unwrap_err(), Errno::ENOENT);
    }

    #[test]
    fn settlement_verifies_emptiness_and_propagates_failures() {
        if super::super::isolate_process_test(
            "NVX_CGROUP_SETTLEMENT_TEST_CHILD",
            "guest::managed_agent::cgroup::tests::settlement_verifies_emptiness_and_propagates_failures",
        ) {
            return;
        }
        let _process = super::super::PROCESS_TEST_LOCK.lock().unwrap();
        let (_temporary, mut system) = setup();
        let execution = system.paths.cgroup_root.join("nvx-exec");
        settle(&mut system).unwrap();
        assert_eq!(std::fs::read(execution.join("cgroup.kill")).unwrap(), b"1");

        std::fs::remove_file(execution.join("cgroup.kill")).unwrap();
        assert_eq!(settle(&mut system).unwrap_err(), Errno::ENOENT);
        std::fs::write(execution.join("cgroup.kill"), b"").unwrap();
        std::fs::write(execution.join("pids.current"), b"bad\n").unwrap();
        assert_eq!(settle(&mut system).unwrap_err(), Errno::EPROTO);
    }

    #[test]
    fn verification_reaps_orphaned_children() {
        if super::super::isolate_process_test(
            "NVX_CGROUP_REAP_TEST_CHILD",
            "guest::managed_agent::cgroup::tests::verification_reaps_orphaned_children",
        ) {
            return;
        }
        let _process = super::super::PROCESS_TEST_LOCK.lock().unwrap();
        let (_temporary, system) = setup();
        let mut child = Command::new("/bin/true").spawn().unwrap();
        let process = ProcessId::from_child(&child);
        while !sys::has_exited(process).unwrap() {
            std::thread::yield_now();
        }
        assert!(!verify_empty(&system).unwrap());
        assert_eq!(sys::wait(process), None);
        let _ = child.wait();
    }

    #[test]
    fn unreaped_tasks_at_deadline_are_not_settled() {
        if super::super::isolate_process_test(
            "NVX_CGROUP_DEADLINE_TEST_CHILD",
            "guest::managed_agent::cgroup::tests::unreaped_tasks_at_deadline_are_not_settled",
        ) {
            return;
        }
        let _process = super::super::PROCESS_TEST_LOCK.lock().unwrap();
        let (_temporary, mut system) = setup();
        std::fs::write(
            system.paths.cgroup_root.join("nvx-exec/pids.current"),
            b"1\n",
        )
        .unwrap();
        assert_eq!(settle(&mut system).unwrap_err(), Errno::ETIMEDOUT);
    }
}
