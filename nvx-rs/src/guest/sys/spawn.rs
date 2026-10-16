//! Prepared fork/exec boundary for the managed guest agent.
//!
//! The safe API owns or borrows every string and descriptor before `fork`. The child branch
//! performs no allocation, locking, formatting, or Rust cleanup: it makes direct system calls
//! over prevalidated storage and ends in `execve`, `execv`, or `_exit`. It makes them through
//! `nix` where its wrappers neither allocate nor consume an owner, and through libc to close a
//! borrowed descriptor, fill the preallocated `PWD` entry, execute, and exit.

use std::ffi::CString;

use nix::fcntl::{FcntlArg, FdFlag, OFlag};
use nix::sys::stat::Mode;
use nix::unistd::{ForkResult, Gid, Pid, Uid};

use super::{Errno, FileDescriptor, ProcessId};

/// Prefix of the mutable physical-working-directory environment entry.
const PWD_PREFIX: &[u8] = b"PWD=";

/// Child report stage for a working-directory failure.
pub(crate) const CHILD_STAGE_CWD: i32 = 1;
/// Child report stage for identity, descriptor, or cgroup setup failure.
pub(crate) const CHILD_STAGE_SETUP: i32 = 2;

/// Privileged setup performed between `fork` and `exec`.
enum ChildSetup {
    /// Direct-agent identity transition, directory entry, and cgroup enrollment.
    Direct {
        /// Workload effective user.
        uid: Uid,
        /// Workload effective group.
        gid: Gid,
        /// Writable direct-workload cgroup membership file.
        cgroup_procs: FileDescriptor,
    },
    /// Sandbox launcher, which performs its own setup.
    Sandbox,
    /// Unprivileged test workload that only enters a directory.
    #[cfg(all(test, feature = "host"))]
    Plain,
}

/// Mutable physical-working-directory entry prepared before `fork`.
///
/// The type is opaque outside the system layer so safe callers cannot choose its storage,
/// environment position, prefix, or terminator independently.
pub(crate) struct PhysicalPwd {
    /// Writable `PWD=` entry, including capacity for the path and its trailing NUL.
    entry: Box<[u8]>,
    /// Position of the entry in the child environment.
    index: usize,
}

impl PhysicalPwd {
    /// Allocates a physical `PWD` entry and removes the entry it will replace.
    pub(crate) fn new(environment: &mut Vec<CString>, length: usize) -> Result<Self, Errno> {
        if length <= PWD_PREFIX.len() {
            return Err(Errno::EINVAL);
        }
        let index = environment
            .iter()
            .position(|entry| entry.as_bytes().starts_with(PWD_PREFIX))
            .map_or(environment.len(), |index| {
                environment.remove(index);
                index
            });
        let mut entry = vec![0u8; length].into_boxed_slice();
        entry[..PWD_PREFIX.len()].copy_from_slice(PWD_PREFIX);
        Ok(Self { entry, index })
    }
}

/// All allocated inputs to one fork/exec operation.
pub(crate) struct SpawnPlan {
    /// Executable path.
    program: CString,
    /// Argument strings, including argument zero.
    arguments: Vec<CString>,
    /// Explicit environment, or `None` to inherit it with `execv`.
    environment: Option<Vec<CString>>,
    /// Preallocated `PWD=` entry filled after the child enters a noncanonical path.
    physical_pwd: Option<PhysicalPwd>,
    /// Working directory used by direct and plain children.
    directory: CString,
    /// Child setup variant.
    setup: ChildSetup,
    /// Read-only null device opened for standard input.
    null_device: CString,
}

impl SpawnPlan {
    /// Creates a plan for the direct or sandbox managed launcher.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn managed(
        program: CString,
        arguments: Vec<CString>,
        environment: Vec<CString>,
        physical_pwd: Option<PhysicalPwd>,
        directory: CString,
        uid: u32,
        gid: u32,
        cgroup_procs: Option<FileDescriptor>,
        null_device: CString,
        direct: bool,
    ) -> Result<Self, Errno> {
        let setup = if direct {
            ChildSetup::Direct {
                uid: Uid::from_raw(uid),
                gid: Gid::from_raw(gid),
                cgroup_procs: cgroup_procs.ok_or(Errno::EBADF)?,
            }
        } else {
            ChildSetup::Sandbox
        };
        let plan = Self {
            program,
            arguments,
            environment: Some(environment),
            physical_pwd,
            directory,
            setup,
            null_device,
        };
        plan.validate()?;
        Ok(plan)
    }

    /// Creates a plan for an unprivileged process with inherited environment.
    #[cfg(all(test, feature = "host"))]
    pub(crate) fn plain(
        program: CString,
        arguments: Vec<CString>,
        directory: CString,
        null_device: CString,
    ) -> Self {
        Self {
            program,
            arguments,
            environment: None,
            physical_pwd: None,
            directory,
            setup: ChildSetup::Plain,
            null_device,
        }
    }

    /// Returns the prepared arguments for focused launch-plan tests.
    #[cfg(test)]
    pub(crate) fn arguments(&self) -> &[CString] {
        &self.arguments
    }

    /// Returns the prepared executable path for focused launch-plan tests.
    #[cfg(test)]
    pub(crate) fn program(&self) -> &CString {
        &self.program
    }

    /// Returns the prepared explicit environment for focused launch-plan tests.
    #[cfg(test)]
    pub(crate) fn environment(&self) -> &[CString] {
        self.environment.as_deref().unwrap_or_default()
    }

    /// Returns the preallocated physical-PWD entry for focused launch-plan tests.
    #[cfg(test)]
    pub(crate) fn physical_pwd(&self) -> Option<&[u8]> {
        self.physical_pwd
            .as_ref()
            .map(|physical_pwd| physical_pwd.entry.as_ref())
    }

    /// Returns the insertion position of the physical-PWD entry.
    #[cfg(test)]
    pub(crate) fn physical_pwd_index(&self) -> Option<usize> {
        self.physical_pwd
            .as_ref()
            .map(|physical_pwd| physical_pwd.index)
    }

    /// Returns whether this plan owns a direct cgroup membership descriptor.
    #[cfg(test)]
    pub(crate) fn has_cgroup(&self) -> bool {
        matches!(&self.setup, ChildSetup::Direct { .. })
    }

    /// Verifies all invariants consumed by the post-fork child.
    fn validate(&self) -> Result<(), Errno> {
        let Some(physical_pwd) = &self.physical_pwd else {
            return Ok(());
        };
        let Some(environment) = &self.environment else {
            return Err(Errno::EINVAL);
        };
        if !matches!(&self.setup, ChildSetup::Direct { .. })
            || physical_pwd.entry.len() <= PWD_PREFIX.len()
            || !physical_pwd.entry.starts_with(PWD_PREFIX)
            || physical_pwd.entry.last() != Some(&0)
            || physical_pwd.index > environment.len()
        {
            return Err(Errno::EINVAL);
        }
        Ok(())
    }
}

/// Descriptor actions prepared for one child.
pub(crate) struct SpawnDescriptors<'a> {
    /// Sealed execution configuration.
    config: &'a FileDescriptor,
    /// Parent's stdout read end, closed in the child.
    stdout_reader: &'a FileDescriptor,
    /// Child's stdout write end.
    stdout_writer: &'a FileDescriptor,
    /// Parent's stderr read end, closed in the child.
    stderr_reader: &'a FileDescriptor,
    /// Child's stderr write end.
    stderr_writer: &'a FileDescriptor,
    /// Optional parent's launch-report read end.
    launch_reader: Option<&'a FileDescriptor>,
    /// Optional child's launch-report write end.
    launch_writer: Option<&'a FileDescriptor>,
    /// Whether the configuration descriptor must survive `exec`.
    inherit_config: bool,
}

impl<'a> SpawnDescriptors<'a> {
    /// Creates a managed-child descriptor action set.
    pub(crate) fn managed(
        config: &'a FileDescriptor,
        stdout: (&'a FileDescriptor, &'a FileDescriptor),
        stderr: (&'a FileDescriptor, &'a FileDescriptor),
        launch: Option<(&'a FileDescriptor, &'a FileDescriptor)>,
    ) -> Self {
        Self {
            config,
            stdout_reader: stdout.0,
            stdout_writer: stdout.1,
            stderr_reader: stderr.0,
            stderr_writer: stderr.1,
            launch_reader: launch.map(|pair| pair.0),
            launch_writer: launch.map(|pair| pair.1),
            inherit_config: true,
        }
    }

    /// Creates an unprivileged-child descriptor action set.
    #[cfg(all(test, feature = "host"))]
    pub(crate) fn plain(
        config: &'a FileDescriptor,
        stdout: (&'a FileDescriptor, &'a FileDescriptor),
        stderr: (&'a FileDescriptor, &'a FileDescriptor),
        launch: Option<(&'a FileDescriptor, &'a FileDescriptor)>,
    ) -> Self {
        Self {
            config,
            stdout_reader: stdout.0,
            stdout_writer: stdout.1,
            stderr_reader: stderr.0,
            stderr_writer: stderr.1,
            launch_reader: launch.map(|pair| pair.0),
            launch_writer: launch.map(|pair| pair.1),
            inherit_config: false,
        }
    }
}

/// Forks and executes one fully prepared plan.
///
/// This function is safe because every pointer and descriptor action is derived from live
/// owners borrowed for the call, and the child path never returns into Rust. `fork` may occur in
/// a multithreaded test process: the child makes only direct async-signal-safe system calls over
/// storage allocated before the fork. Production invokes it from the single-threaded managed
/// agent.
pub(crate) fn spawn(
    plan: &mut SpawnPlan,
    descriptors: SpawnDescriptors<'_>,
) -> Result<ProcessId, Errno> {
    plan.validate()?;
    let mut argument_pointers: Vec<_> = plan
        .arguments
        .iter()
        .map(|argument| argument.as_ptr())
        .collect();
    argument_pointers.push(std::ptr::null());
    let physical = plan.physical_pwd.as_mut().map(|physical_pwd| {
        physical_pwd
            .entry
            .as_mut_ptr()
            .cast::<nix::libc::c_char>()
            .cast_const()
    });
    let environment_pointers = plan.environment.as_ref().map(|environment| {
        let mut pointers =
            Vec::with_capacity(environment.len() + usize::from(plan.physical_pwd.is_some()) + 1);
        for index in 0..=environment.len() {
            if plan
                .physical_pwd
                .as_ref()
                .is_some_and(|physical_pwd| physical_pwd.index == index)
                && let Some(pointer) = physical
            {
                pointers.push(pointer);
            }
            if let Some(entry) = environment.get(index) {
                pointers.push(entry.as_ptr());
            }
        }
        pointers.push(std::ptr::null());
        pointers
    });

    // SAFETY: all child inputs and pointer vectors were allocated above. The child invokes only
    // the non-returning routine below; the parent returns a typed process identifier.
    match unsafe { nix::unistd::fork() }? {
        ForkResult::Child => {
            // SAFETY: this is the post-fork child and `child_exec` never returns.
            unsafe {
                child_exec(
                    plan,
                    &argument_pointers,
                    environment_pointers.as_deref(),
                    &descriptors,
                )
            }
        }
        ForkResult::Parent { child } => {
            // A racing exec or exit makes a failed setpgid harmless, exactly as in the C agent.
            let _ = nix::unistd::setpgid(child, child);
            Ok(ProcessId::from_pid(child))
        }
    }
}

/// Executes the child half of [`spawn`].
///
/// # Safety
///
/// This must run only in the just-forked child. Every pointer and descriptor must refer to
/// storage retained by the copied parent stack until the function ends in `exec` or `_exit`.
unsafe fn child_exec(
    plan: &mut SpawnPlan,
    arguments: &[*const nix::libc::c_char],
    environment: Option<&[*const nix::libc::c_char]>,
    descriptors: &SpawnDescriptors<'_>,
) -> ! {
    let _ = nix::unistd::setpgid(Pid::from_raw(0), Pid::from_raw(0));
    if descriptors.inherit_config
        && nix::fcntl::fcntl(
            descriptors.config.borrowed(),
            FcntlArg::F_SETFD(FdFlag::empty()),
        )
        .is_err()
    {
        // SAFETY: the caller establishes that this is the post-fork child.
        unsafe { exit_child() }
    }
    // SAFETY: the caller establishes that this is the post-fork child, whose copies of these
    // descriptors no Rust owner closes.
    unsafe {
        close_copy(descriptors.stdout_reader);
        close_copy(descriptors.stderr_reader);
        if !descriptors.inherit_config {
            close_copy(descriptors.config);
        }
    }
    if let Ok(null) = nix::fcntl::open(plan.null_device.as_c_str(), OFlag::O_RDONLY, Mode::empty())
    {
        let _ = nix::unistd::dup2_stdin(&null);
        let _ = nix::unistd::close(null);
    }
    let _ = nix::unistd::dup2_stdout(descriptors.stdout_writer.borrowed());
    let _ = nix::unistd::dup2_stderr(descriptors.stderr_writer.borrowed());
    // SAFETY: as above.
    unsafe {
        close_copy(descriptors.stdout_writer);
        close_copy(descriptors.stderr_writer);
    }

    match &mut plan.setup {
        ChildSetup::Direct {
            uid,
            gid,
            cgroup_procs,
        } => {
            let (Some(launch_reader), Some(launch_writer)) =
                (descriptors.launch_reader, descriptors.launch_writer)
            else {
                // SAFETY: as above.
                unsafe { exit_child() }
            };
            // SAFETY: as above, and every failure report below runs in this child too.
            unsafe {
                close_copy(launch_reader);
                if nix::unistd::setgroups(&[]).is_err()
                    || nix::unistd::setegid(*gid).is_err()
                    || nix::unistd::seteuid(*uid).is_err()
                {
                    report_failure(launch_writer, CHILD_STAGE_SETUP);
                }
                if nix::unistd::chdir(plan.directory.as_c_str()).is_err() {
                    report_failure(launch_writer, CHILD_STAGE_CWD);
                }
                if nix::unistd::seteuid(Uid::from_raw(0)).is_err()
                    || nix::unistd::setegid(Gid::from_raw(0)).is_err()
                {
                    report_failure(launch_writer, CHILD_STAGE_SETUP);
                }
                if let Some(physical_pwd) = plan.physical_pwd.as_mut() {
                    let output = &mut physical_pwd.entry[PWD_PREFIX.len()..];
                    // `nix`'s `getcwd` allocates its result, so libc fills the entry in place.
                    if nix::libc::getcwd(output.as_mut_ptr().cast(), output.len()).is_null() {
                        report_failure(launch_writer, CHILD_STAGE_SETUP);
                    }
                }
                if !write_decimal(cgroup_procs, nix::unistd::getpid().as_raw()) {
                    report_failure(launch_writer, CHILD_STAGE_SETUP);
                }
                close_copy(cgroup_procs);
            }
        }
        ChildSetup::Sandbox => {}
        #[cfg(all(test, feature = "host"))]
        ChildSetup::Plain => {
            // SAFETY: as above.
            unsafe {
                if let Some(reader) = descriptors.launch_reader {
                    close_copy(reader);
                }
                if let Some(writer) = descriptors.launch_writer {
                    close_copy(writer);
                }
                if nix::unistd::chdir(plan.directory.as_c_str()).is_err() {
                    exit_child();
                }
            }
        }
    }

    // `nix`'s `exec` wrappers allocate their pointer vectors, so libc takes the ones that the
    // parent prepared.
    // SAFETY: the vectors are NUL-terminated, and every pointer names storage retained by the
    // copied parent stack.
    unsafe {
        if let Some(environment) = environment {
            nix::libc::execve(
                plan.program.as_ptr(),
                arguments.as_ptr(),
                environment.as_ptr(),
            );
        } else {
            nix::libc::execv(plan.program.as_ptr(), arguments.as_ptr());
        }
        exit_child()
    }
}

/// Closes the child's copy of a descriptor that a parent-side owner borrowed into the child.
///
/// `nix`'s `close` consumes an owner, which the child has only borrowed.
///
/// # Safety
///
/// This must run only in a post-fork child that never returns into Rust, so that no owner
/// closes the descriptor again.
unsafe fn close_copy(descriptor: &FileDescriptor) {
    // SAFETY: the caller guarantees that no Rust owner in this process uses the copy again.
    unsafe { nix::libc::close(descriptor.raw()) };
}

/// Leaves the post-fork child with status 125 without running Rust or C cleanup.
///
/// `nix` has no `_exit`, and `std::process::exit` runs cleanup.
///
/// # Safety
///
/// This must run only in a post-fork child.
unsafe fn exit_child() -> ! {
    // SAFETY: the caller guarantees that this is the post-fork child.
    unsafe { nix::libc::_exit(125) }
}

/// Reports a direct-child setup failure and exits immediately.
///
/// # Safety
///
/// `descriptor` must be the live launch-report writer in a post-fork child.
unsafe fn report_failure(descriptor: &FileDescriptor, stage: i32) -> ! {
    let status = Errno::last_raw();
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&stage.to_ne_bytes());
    bytes[4..].copy_from_slice(&status.to_ne_bytes());
    let _ = write_all(descriptor, &bytes);
    // SAFETY: the caller guarantees that this is the post-fork child.
    unsafe { exit_child() }
}

/// Writes a decimal process ID and newline without allocation.
fn write_decimal(descriptor: &FileDescriptor, value: nix::libc::pid_t) -> bool {
    let mut bytes = [0u8; 32];
    let mut position = bytes.len() - 1;
    bytes[position] = b'\n';
    let mut value = value as u32;
    loop {
        position -= 1;
        bytes[position] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    write_all(descriptor, &bytes[position..])
}

/// Writes all bytes with direct async-signal-safe calls, retrying interruptions.
fn write_all(descriptor: &FileDescriptor, mut bytes: &[u8]) -> bool {
    while !bytes.is_empty() {
        match nix::unistd::write(descriptor.borrowed(), bytes) {
            Ok(count) if count > 0 => bytes = &bytes[count..],
            Err(Errno::EINTR) => {}
            Ok(_) | Err(_) => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns one ordinary owned descriptor for plan and action tests.
    fn descriptor() -> FileDescriptor {
        FileDescriptor::from_owned(tempfile::tempfile().unwrap().into())
    }

    /// Builds a minimal managed plan with `physical_pwd`.
    fn managed_plan(
        environment: Vec<CString>,
        physical_pwd: Option<PhysicalPwd>,
        direct: bool,
    ) -> Result<SpawnPlan, Errno> {
        SpawnPlan::managed(
            c"/bin/true".to_owned(),
            vec![c"/bin/true".to_owned()],
            environment,
            physical_pwd,
            c"/".to_owned(),
            1,
            1,
            direct.then(descriptor),
            c"/dev/null".to_owned(),
            direct,
        )
    }

    #[test]
    fn physical_pwd_is_built_entirely_in_the_system_layer() {
        let mut environment = vec![
            c"FIRST=1".to_owned(),
            c"PWD=/old".to_owned(),
            c"LAST=1".to_owned(),
        ];
        let physical_pwd = PhysicalPwd::new(&mut environment, 32).unwrap();
        assert_eq!(physical_pwd.index, 1);
        assert_eq!(environment, [c"FIRST=1".to_owned(), c"LAST=1".to_owned()]);
        assert!(physical_pwd.entry.starts_with(PWD_PREFIX));
        assert_eq!(physical_pwd.entry.last(), Some(&0));
        assert_eq!(
            PhysicalPwd::new(&mut environment, PWD_PREFIX.len()).err(),
            Some(Errno::EINVAL)
        );
    }

    #[test]
    fn managed_plan_rejects_every_invalid_physical_pwd_invariant() {
        let mut environment = vec![c"VALUE=1".to_owned()];
        let physical_pwd = PhysicalPwd::new(&mut environment, 32).unwrap();
        assert_eq!(
            managed_plan(environment, Some(physical_pwd), false).err(),
            Some(Errno::EINVAL)
        );

        let mut environment = vec![c"VALUE=1".to_owned()];
        let mut physical_pwd = PhysicalPwd::new(&mut environment, 32).unwrap();
        physical_pwd.entry[0] = b'X';
        assert_eq!(
            managed_plan(environment, Some(physical_pwd), true).err(),
            Some(Errno::EINVAL)
        );

        let mut environment = vec![c"VALUE=1".to_owned()];
        let mut physical_pwd = PhysicalPwd::new(&mut environment, 32).unwrap();
        *physical_pwd.entry.last_mut().unwrap() = b'X';
        assert_eq!(
            managed_plan(environment, Some(physical_pwd), true).err(),
            Some(Errno::EINVAL)
        );

        let mut environment = vec![c"VALUE=1".to_owned()];
        let mut physical_pwd = PhysicalPwd::new(&mut environment, 32).unwrap();
        physical_pwd.index = environment.len() + 1;
        assert_eq!(
            managed_plan(environment, Some(physical_pwd), true).err(),
            Some(Errno::EINVAL)
        );
    }

    #[test]
    fn spawn_rejects_a_corrupted_plan_before_forking() {
        let mut environment = vec![c"VALUE=1".to_owned()];
        let physical_pwd = PhysicalPwd::new(&mut environment, 32).unwrap();
        let mut plan = managed_plan(environment, Some(physical_pwd), true).unwrap();
        plan.physical_pwd.as_mut().unwrap().entry[0] = b'X';
        let action = descriptor();
        let descriptors = SpawnDescriptors::managed(
            &action,
            (&action, &action),
            (&action, &action),
            Some((&action, &action)),
        );
        assert_eq!(spawn(&mut plan, descriptors).err(), Some(Errno::EINVAL));
    }
}
