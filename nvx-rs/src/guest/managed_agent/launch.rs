use std::os::unix::ffi::OsStrExt;

use crate::guest::parse::parse_decimal;
use crate::guest::sys::{self, Errno, FileDescriptor, Mode, OpenFlags, ProcessId, c_string};
use crate::protocol::GuestExecPayload;

use super::AgentConfig;
use super::environment;
use super::seam::{Paths, path_c_string};

/// Child report stage for failure to enter the requested working directory.
pub(crate) const LAUNCH_STAGE_CWD: i32 = sys::CHILD_STAGE_CWD;
/// Borrowed launch inputs and owned descriptor endpoints prepared by the execution engine.
pub(crate) struct SpawnRequest<'a> {
    /// Agent mode and configured workload identity.
    pub(crate) config: &'a AgentConfig,
    /// Decoded workload request.
    pub(crate) execution: &'a GuestExecPayload,
    /// Sealed helper configuration.
    pub(crate) config_fd: &'a FileDescriptor,
    /// Parent reader and child writer for standard output.
    pub(crate) stdout_pipe: (&'a FileDescriptor, &'a FileDescriptor),
    /// Parent reader and child writer for standard error.
    pub(crate) stderr_pipe: (&'a FileDescriptor, &'a FileDescriptor),
    /// Direct-child launch report pipe, absent in sandbox mode.
    pub(crate) launch_pipe: Option<(&'a FileDescriptor, &'a FileDescriptor)>,
}

/// Safe, fully allocated fork/exec plan.
struct Plan {
    /// System-layer plan that owns every child input.
    inner: sys::SpawnPlan,
}

/// Builds a launch plan and crosses the safe fork/exec boundary.
pub(crate) fn spawn(paths: &Paths, request: SpawnRequest<'_>) -> Result<ProcessId, Errno> {
    let mut plan = Plan::new(paths, &request)?;
    let descriptors = sys::SpawnDescriptors::managed(
        request.config_fd,
        request.stdout_pipe,
        request.stderr_pipe,
        request.launch_pipe,
    );
    sys::spawn(&mut plan.inner, descriptors)
}

impl Plan {
    /// Allocates and validates every input needed after `fork`.
    fn new(paths: &Paths, request: &SpawnRequest<'_>) -> Result<Self, Errno> {
        let config_fd = request.config_fd.argument();
        let directory = c_string(request.execution.cwd.as_deref().unwrap_or(b"/"))?;
        let uid = parse_id(request.config.uid.as_bytes())?;
        let gid = parse_id(request.config.gid.as_bytes())?;
        let helper = path_c_string(&paths.helper)?;
        let launcher = path_c_string(&paths.launcher)?;
        let setpriv = path_c_string(&paths.setpriv)?;
        let mut arguments = Vec::new();
        let program;
        let mut environment = environment::inherited()?;
        let mut physical_pwd = None;
        if request.config.direct {
            program = setpriv;
            for value in [
                b"setpriv".as_slice(),
                b"--reuid",
                request.config.uid.as_bytes(),
                b"--regid",
                request.config.gid.as_bytes(),
                b"--clear-groups",
                b"--no-new-privs",
                b"--bounding-set=-all",
                b"--inh-caps=-all",
                b"--ambient-caps=-all",
                helper.as_bytes(),
                b"--exec-config-fd",
                config_fd.as_bytes(),
                b"--",
            ] {
                arguments.push(c_string(value)?);
            }
            environment::set(&mut environment, b"HOME", request.config.home.as_bytes())?;
            environment::set(&mut environment, b"USER", request.config.user.as_bytes())?;
            environment::set(&mut environment, b"LOGNAME", request.config.user.as_bytes())?;
            if request.execution.environment.is_none() || request.execution.inherit_default_env {
                if directory.to_bytes() == b"/" || super::helper::safe_path(directory.to_bytes()) {
                    environment::set(&mut environment, b"PWD", directory.to_bytes())?;
                } else {
                    physical_pwd = Some(sys::PhysicalPwd::new(
                        &mut environment,
                        b"PWD=".len() + crate::protocol::MAX_ARGUMENT_BYTES,
                    )?);
                }
            }
        } else {
            program = launcher.clone();
            for value in [
                launcher.as_bytes(),
                paths.barrier.as_os_str().as_bytes(),
                request.config.rootfs.as_bytes(),
                request.config.hostname.as_bytes(),
                request.config.uid.as_bytes(),
                request.config.gid.as_bytes(),
                request.config.user.as_bytes(),
                request.config.home.as_bytes(),
            ] {
                arguments.push(c_string(value)?);
            }
            environment::set(
                &mut environment,
                b"NVX_EXEC_CONFIG_FD",
                config_fd.as_bytes(),
            )?;
        }
        for argument in &request.execution.argv {
            arguments.push(c_string(argument)?);
        }
        let cgroup_procs = if request.config.direct {
            let path = path_c_string(&paths.cgroup_root.join("nvx-exec/cgroup.procs"))?;
            Some(sys::open(
                &path,
                OpenFlags::O_WRONLY | OpenFlags::O_CLOEXEC,
                Mode::empty(),
            )?)
        } else {
            None
        };
        Ok(Self {
            inner: sys::SpawnPlan::managed(
                program,
                arguments,
                environment,
                physical_pwd,
                directory,
                uid,
                gid,
                cgroup_procs,
                path_c_string(&paths.null_device)?,
                request.config.direct,
            )?,
        })
    }
}

/// Parses one nonzero decimal UID or GID while excluding the unchanged-ID sentinel.
fn parse_id(text: &[u8]) -> Result<u32, Errno> {
    parse_decimal(text)
        .filter(|&id| id != 0 && id < u64::from(u32::MAX))
        .and_then(|id| u32::try_from(id).ok())
        .ok_or(Errno::EINVAL)
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use crate::protocol::GuestExecPayload;

    use super::*;

    fn config(direct: bool) -> AgentConfig {
        AgentConfig {
            rootfs: CString::new(if direct { "-" } else { "/rootfs" }).unwrap(),
            hostname: c"sandbox".to_owned(),
            uid: c"1000".to_owned(),
            gid: c"1001".to_owned(),
            user: c"workload".to_owned(),
            home: c"/home/workload".to_owned(),
            direct,
        }
    }

    fn execution() -> GuestExecPayload {
        GuestExecPayload {
            timeout_ms: 0,
            argv: vec![b"/bin/echo".to_vec(), b"ok".to_vec()],
            cwd: Some(b"/work".to_vec()),
            environment: None,
            inherit_default_env: false,
        }
    }

    fn descriptor() -> FileDescriptor {
        FileDescriptor::from_owned(tempfile::tempfile().unwrap().into())
    }

    fn request<'a>(
        config: &'a AgentConfig,
        execution: &'a GuestExecPayload,
        descriptor: &'a FileDescriptor,
    ) -> SpawnRequest<'a> {
        SpawnRequest {
            config,
            execution,
            config_fd: descriptor,
            stdout_pipe: (descriptor, descriptor),
            stderr_pipe: (descriptor, descriptor),
            launch_pipe: Some((descriptor, descriptor)),
        }
    }

    #[test]
    fn direct_launch_uses_setpriv_and_clears_every_capability_set() {
        let temporary = tempfile::tempdir().unwrap();
        std::fs::create_dir(temporary.path().join("nvx-exec")).unwrap();
        std::fs::write(temporary.path().join("nvx-exec/cgroup.procs"), b"").unwrap();
        let paths = Paths {
            cgroup_root: temporary.path().to_owned(),
            setpriv: "/test/setpriv".into(),
            helper: "/test/nvx-managed-agent".into(),
            ..Paths::default()
        };
        let config = config(true);
        let execution = execution();
        let descriptor = descriptor();
        let descriptor_argument = descriptor.argument();
        let plan = Plan::new(&paths, &request(&config, &execution, &descriptor)).unwrap();
        let arguments: Vec<_> = plan
            .inner
            .arguments()
            .iter()
            .map(|argument| argument.to_bytes())
            .collect();
        assert_eq!(
            arguments,
            [
                b"setpriv".as_slice(),
                b"--reuid",
                b"1000",
                b"--regid",
                b"1001",
                b"--clear-groups",
                b"--no-new-privs",
                b"--bounding-set=-all",
                b"--inh-caps=-all",
                b"--ambient-caps=-all",
                b"/test/nvx-managed-agent",
                b"--exec-config-fd",
                descriptor_argument.as_bytes(),
                b"--",
                b"/bin/echo",
                b"ok",
            ]
        );
        assert_eq!(plan.inner.program().as_bytes(), b"/test/setpriv");
        let environment: Vec<_> = plan
            .inner
            .environment()
            .iter()
            .map(|entry| entry.to_bytes())
            .collect();
        for expected in [
            b"HOME=/home/workload".as_slice(),
            b"USER=workload",
            b"LOGNAME=workload",
            b"PWD=/work",
        ] {
            assert!(environment.contains(&expected), "{expected:?}");
        }
        assert!(plan.inner.has_cgroup());
    }

    #[test]
    fn sandbox_launch_exports_only_the_deliberate_config_descriptor() {
        let paths = Paths {
            launcher: "/test/nvx-container-launch".into(),
            barrier: "/test/start".into(),
            ..Paths::default()
        };
        let config = config(false);
        let execution = execution();
        let descriptor = descriptor();
        let plan = Plan::new(&paths, &request(&config, &execution, &descriptor)).unwrap();
        let arguments: Vec<_> = plan
            .inner
            .arguments()
            .iter()
            .map(|argument| argument.to_bytes())
            .collect();
        assert_eq!(
            arguments,
            [
                b"/test/nvx-container-launch".as_slice(),
                b"/test/start",
                b"/rootfs",
                b"sandbox",
                b"1000",
                b"1001",
                b"workload",
                b"/home/workload",
                b"/bin/echo",
                b"ok",
            ]
        );
        assert!(
            plan.inner
                .environment()
                .iter()
                .any(|entry| entry.as_bytes().starts_with(b"NVX_EXEC_CONFIG_FD="))
        );
        assert!(!plan.inner.has_cgroup());
    }

    #[test]
    fn workload_ids_are_nonzero_decimal_and_not_the_unchanged_value() {
        for (text, expected) in [
            (b"1".as_slice(), Some(1)),
            (b"1000", Some(1000)),
            (b"4294967294", Some(u32::MAX - 1)),
            (b"0", None),
            (b"4294967295", None),
            (b"4294967296", None),
            (b"+1", None),
            (b"-1", None),
            (b" 1", None),
            (b"1x", None),
        ] {
            assert_eq!(parse_id(text).ok(), expected, "{text:?}");
        }
    }

    #[test]
    fn direct_pwd_is_deferred_only_for_noncanonical_names() {
        let temporary = tempfile::tempdir().unwrap();
        std::fs::create_dir(temporary.path().join("nvx-exec")).unwrap();
        std::fs::write(temporary.path().join("nvx-exec/cgroup.procs"), b"").unwrap();
        let paths = Paths {
            cgroup_root: temporary.path().to_owned(),
            ..Paths::default()
        };
        let config = config(true);
        for cwd in [b"/a/./b".as_slice(), b"/a/../b", b"/a//b", b"/a/b/"] {
            let execution = GuestExecPayload {
                cwd: Some(cwd.to_vec()),
                ..execution()
            };
            let descriptor = descriptor();
            let plan = Plan::new(&paths, &request(&config, &execution, &descriptor)).unwrap();
            let slot = plan.inner.physical_pwd().expect("PWD is deferred");
            assert_eq!(&slot[..4], b"PWD=");
            assert!(slot[4..].iter().all(|&byte| byte == 0));
            assert!(
                plan.inner
                    .environment()
                    .iter()
                    .all(|entry| !entry.as_bytes().starts_with(b"PWD="))
            );
            assert!(plan.inner.physical_pwd_index().is_some());
            assert!(plan.inner.has_cgroup());
        }

        let execution = GuestExecPayload {
            cwd: Some(b"/symlinked/component".to_vec()),
            ..execution()
        };
        let descriptor = descriptor();
        let plan = Plan::new(&paths, &request(&config, &execution, &descriptor)).unwrap();
        assert!(plan.inner.physical_pwd().is_none());
        assert!(
            plan.inner
                .environment()
                .iter()
                .any(|entry| entry.as_bytes() == b"PWD=/symlinked/component")
        );
        assert!(plan.inner.has_cgroup());
    }
}
