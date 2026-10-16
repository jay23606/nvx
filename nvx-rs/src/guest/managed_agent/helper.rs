use std::ffi::{CStr, CString};

use crate::guest::status::CommandError;
use crate::guest::sys::{self, Errno, c_string};

use super::diagnostics::{with_description, write_stderr};
use super::environment;
use super::exec_config::{self, HelperConfig};
use super::seam::System;

/// Runs the short-lived execution-helper mode.
///
/// Every failure is [`CommandError::Agent`]. As in the C helper, only working-directory,
/// environment, and `exec` failures print why.
pub(crate) fn run(system: &mut impl System, arguments: &[CString]) -> Result<(), CommandError> {
    if arguments.len() < 5
        || arguments[1].as_bytes() != b"--exec-config-fd"
        || arguments[3].as_bytes() != b"--"
        || arguments[4].as_bytes().first() != Some(&b'/')
    {
        return Err(CommandError::Agent);
    }
    let config = read_config(system, &arguments[2]).map_err(|_| CommandError::Agent)?;
    if let Some(cwd) = &config.cwd
        && (cwd.first() != Some(&b'/') || cwd.contains(&0))
    {
        write_stderr(b"nvx-managed-agent: invalid working directory\n");
        return Err(CommandError::Agent);
    }
    let mut environment = environment::inherited().map_err(|_| CommandError::Agent)?;
    environment::unset(&mut environment, b"NVX_EXEC_CONFIG_FD");
    if !config.cwd_entered {
        enter_directory(system, &config, &mut environment)?;
    }
    if let Some(entries) = &config.environment {
        if !config.inherit_default_env {
            environment.clear();
        }
        for entry in entries {
            put(system, &mut environment, entry).map_err(|_| CommandError::Agent)?;
        }
    }
    if let Err(error) = system.exec(&arguments[4], &arguments[4..], Some(&environment)) {
        write_stderr(&with_description(
            b"nvx-managed-agent: cannot execute workload: ",
            error,
        ));
        return Err(CommandError::Agent);
    }
    Ok(())
}

/// Reads the sealed configuration through the inherited descriptor that `text` names.
///
/// The configuration's descriptors close no later than the workload's `exec`, as the C helper
/// closed its descriptor before it.
fn read_config(system: &mut impl System, text: &CStr) -> Result<HelperConfig, Errno> {
    let descriptor = system.take_inherited_descriptor(text)?;
    exec_config::read(&descriptor)
}

/// Enters the requested working directory, or `/` without one, and sets `PWD` unless the
/// configuration replaces the inherited environment.
fn enter_directory(
    system: &mut impl System,
    config: &HelperConfig,
    environment: &mut Vec<CString>,
) -> Result<(), CommandError> {
    let directory = config.cwd.as_deref().unwrap_or(b"/");
    let directory_c = c_string(directory).map_err(|_| CommandError::Agent)?;
    if let Err(error) = sys::change_directory(&directory_c) {
        let prefix = [
            b"nvx-managed-agent: cannot use working directory ".as_slice(),
            directory,
            b": ",
        ]
        .concat();
        write_stderr(&with_description(&prefix, error));
        return Err(CommandError::Agent);
    }
    if (config.environment.is_none() || config.inherit_default_env)
        && let Err(error) = set_pwd(system, environment, directory)
    {
        write_stderr(&with_description(
            b"nvx-managed-agent: cannot configure working directory environment: ",
            error,
        ));
        return Err(CommandError::Agent);
    }
    Ok(())
}

/// Sets `PWD` to the requested spelling, or to the physical path of a noncanonical one.
fn set_pwd(
    system: &mut impl System,
    environment: &mut Vec<CString>,
    directory: &[u8],
) -> Result<(), Errno> {
    let pwd = if directory == b"/" || safe_path(directory) {
        directory.to_vec()
    } else {
        sys::current_directory(crate::protocol::MAX_ARGUMENT_BYTES)?
    };
    system.validate_environment(c"PWD", &c_string(&pwd)?)?;
    environment::set(environment, b"PWD", &pwd)
}

/// Sets the variable of one validated `NAME=value` configuration entry, as C's `putenv` did.
fn put(
    system: &mut impl System,
    environment: &mut Vec<CString>,
    entry: &[u8],
) -> Result<(), Errno> {
    let equals = entry
        .iter()
        .position(|&byte| byte == b'=')
        .ok_or(Errno::EINVAL)?;
    let (name, value) = (&entry[..equals], &entry[equals + 1..]);
    system.validate_environment(&c_string(name)?, &c_string(value)?)?;
    environment::set(environment, name, value)
}

/// Returns whether an absolute path has only canonical nonempty components.
pub(crate) fn safe_path(path: &[u8]) -> bool {
    let Some(components) = path.strip_prefix(b"/") else {
        return false;
    };
    !components.is_empty()
        && components
            .split(|&byte| byte == b'/')
            .all(|component| !matches!(component, b"" | b"." | b".."))
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, Write};

    use crate::guest::sys::FileDescriptor;
    use crate::protocol::{self, GuestExecPayload};

    use super::super::seam::{Paths, TestSystem};
    use super::*;

    fn execution(environment: Option<Vec<Vec<u8>>>, inherit: bool) -> GuestExecPayload {
        GuestExecPayload {
            timeout_ms: 0,
            argv: vec![b"/bin/true".to_vec()],
            cwd: None,
            environment,
            inherit_default_env: inherit,
        }
    }

    fn arguments(
        system: &mut TestSystem,
        descriptor: FileDescriptor,
        workload: &[&[u8]],
    ) -> Vec<CString> {
        let mut arguments = vec![
            c_string(b"nvx-managed-agent").unwrap(),
            c_string(b"--exec-config-fd").unwrap(),
            system.transfer_inherited_descriptor(descriptor),
            c_string(b"--").unwrap(),
        ];
        arguments.extend(workload.iter().map(|argument| c_string(argument).unwrap()));
        arguments
    }

    fn file_with(bytes: &[u8]) -> FileDescriptor {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(bytes).unwrap();
        file.rewind().unwrap();
        FileDescriptor::from_owned(file.into())
    }

    /// Returns the inherited environment without the helper's descriptor variable.
    fn inherited() -> Vec<Vec<u8>> {
        let mut environment = environment::inherited().unwrap();
        environment::unset(&mut environment, b"NVX_EXEC_CONFIG_FD");
        environment
            .into_iter()
            .map(|entry| entry.into_bytes())
            .collect()
    }

    /// Returns the environment of the helper's only `exec`.
    fn executed_environment(system: &TestSystem) -> Vec<Vec<u8>> {
        let [(_, _, environment)] = system.execs.as_slice() else {
            panic!("expected one exec, not {}", system.execs.len());
        };
        environment
            .clone()
            .expect("the helper passes an environment")
    }

    #[test]
    fn helper_applies_exact_empty_and_layered_environments() {
        let fd = exec_config::create(&execution(Some(Vec::new()), false), true).unwrap();
        let mut system = TestSystem::new(Paths::default());
        let helper_arguments = arguments(&mut system, fd, &[b"/usr/bin/env"]);
        assert_eq!(run(&mut system, &helper_arguments), Ok(()));
        assert!(executed_environment(&system).is_empty());

        let layered = vec![b"VALUE=layered".to_vec(), b"VALUE=again".to_vec()];
        let fd = exec_config::create(&execution(Some(layered), true), true).unwrap();
        let mut system = TestSystem::new(Paths::default());
        let helper_arguments = arguments(&mut system, fd, &[b"/usr/bin/env"]);
        assert_eq!(run(&mut system, &helper_arguments), Ok(()));
        let mut expected: Vec<_> = inherited()
            .into_iter()
            .map(|entry| CString::new(entry).unwrap())
            .collect();
        environment::set(&mut expected, b"VALUE", b"again").unwrap();
        let expected: Vec<_> = expected.into_iter().map(CString::into_bytes).collect();
        assert_eq!(executed_environment(&system), expected);
    }

    #[test]
    fn helper_rejects_bad_syntax_relative_cwd_and_conflicting_cwd_flags() {
        let mut system = TestSystem::new(Paths::default());
        assert_eq!(
            run(&mut system, &[c_string(b"agent").unwrap()]),
            Err(CommandError::Agent)
        );
        assert!(system.execs.is_empty());

        let mut relative = Vec::new();
        relative.extend_from_slice(&protocol::EXEC_CWD_PRESENT.to_le_bytes());
        relative.extend_from_slice(&0u16.to_le_bytes());
        relative.extend_from_slice(&1u32.to_le_bytes());
        relative.push(b'.');
        let fd = file_with(&relative);
        let helper_arguments = arguments(&mut system, fd, &[b"/bin/pwd"]);
        assert_eq!(
            run(&mut system, &helper_arguments),
            Err(CommandError::Agent)
        );

        let mut conflicting = Vec::new();
        conflicting.extend_from_slice(
            &(protocol::EXEC_CWD_PRESENT | exec_config::EXEC_CWD_ENTERED).to_le_bytes(),
        );
        conflicting.extend_from_slice(&0u16.to_le_bytes());
        conflicting.extend_from_slice(&1u32.to_le_bytes());
        conflicting.push(b'/');
        let fd = file_with(&conflicting);
        let helper_arguments = arguments(&mut system, fd, &[b"/bin/pwd"]);
        assert_eq!(
            run(&mut system, &helper_arguments),
            Err(CommandError::Agent)
        );
        assert!(system.execs.is_empty());
    }

    #[test]
    fn helper_does_not_exec_when_an_environment_export_fails() {
        let fd = exec_config::create(
            &execution(Some(vec![b"VALUE=layered".to_vec()]), true),
            true,
        )
        .unwrap();
        let mut system = TestSystem::new(Paths::default());
        system.fail_environment = Some(b"VALUE".to_vec());
        let helper_arguments = arguments(&mut system, fd, &[b"/bin/true"]);
        assert_eq!(
            run(&mut system, &helper_arguments),
            Err(CommandError::Agent)
        );
        assert!(system.execs.is_empty());
    }

    #[test]
    fn helper_keeps_a_directory_that_the_caller_entered() {
        let fd = exec_config::create(&execution(None, false), true).unwrap();
        let mut system = TestSystem::new(Paths::default());
        let helper_arguments = arguments(&mut system, fd, &[b"/bin/pwd"]);
        assert_eq!(run(&mut system, &helper_arguments), Ok(()));
        assert_eq!(executed_environment(&system), inherited());
        assert_eq!(system.execs[0].1, [b"/bin/pwd".to_vec()]);
    }

    #[test]
    fn safe_working_directory_names_match_the_c_helper() {
        for path in [b"/".as_slice(), b"/tmp", b"/a/b", b"relative"] {
            assert_eq!(
                safe_path(path),
                path != b"/" && path != b"relative",
                "{path:?}"
            );
        }
        for path in [b"/a//b".as_slice(), b"/a/./b", b"/a/../b", b"/a/"] {
            assert!(!safe_path(path), "{path:?}");
        }
    }
}
