use crate::guest::sys::{self, Errno, FileDescriptor};
use crate::protocol::{
    EXEC_CWD_PRESENT, EXEC_ENVIRONMENT_PRESENT, EXEC_INHERIT_DEFAULT_ENV, GuestExecPayload,
};

/// Private helper-format flag indicating that the launcher already entered the cwd.
pub(crate) const EXEC_CWD_ENTERED: u16 = 0x8000;

/// Decoded sealed configuration consumed by helper mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HelperConfig {
    /// Requested absolute working directory, unless already entered.
    pub(crate) cwd: Option<Vec<u8>>,
    /// Exact or layered environment entries.
    pub(crate) environment: Option<Vec<Vec<u8>>>,
    /// Whether explicit entries layer over the inherited environment.
    pub(crate) inherit_default_env: bool,
    /// Whether the privileged child already entered the working directory.
    pub(crate) cwd_entered: bool,
}

/// Encodes `execution` in an immutable close-on-exec memfd.
pub(crate) fn create(
    execution: &GuestExecPayload,
    cwd_entered: bool,
) -> Result<FileDescriptor, Errno> {
    let descriptor = sys::create_memfd(c"nvx-exec-config")?;
    let bytes = encode(execution, cwd_entered)?;
    descriptor.write_all(&bytes)?;
    descriptor.rewind()?;
    descriptor.seal_immutable()?;
    Ok(descriptor)
}

/// Serializes the private helper configuration format.
fn encode(execution: &GuestExecPayload, cwd_entered: bool) -> Result<Vec<u8>, Errno> {
    let mut flags = 0u16;
    let cwd = if cwd_entered {
        flags |= EXEC_CWD_ENTERED;
        None
    } else {
        if execution.cwd.is_some() {
            flags |= EXEC_CWD_PRESENT;
        }
        execution.cwd.as_deref()
    };
    if execution.environment.is_some() {
        flags |= EXEC_ENVIRONMENT_PRESENT;
    }
    if execution.inherit_default_env {
        flags |= EXEC_INHERIT_DEFAULT_ENV;
    }
    let environment = execution.environment.as_deref().unwrap_or_default();
    let count = u16::try_from(environment.len()).map_err(|_| Errno::EOVERFLOW)?;
    let cwd_len = u32::try_from(cwd.map_or(0, <[u8]>::len)).map_err(|_| Errno::EOVERFLOW)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&flags.to_le_bytes());
    bytes.extend_from_slice(&count.to_le_bytes());
    bytes.extend_from_slice(&cwd_len.to_le_bytes());
    if let Some(cwd) = cwd {
        bytes.extend_from_slice(cwd);
    }
    for entry in environment {
        let length = u32::try_from(entry.len()).map_err(|_| Errno::EOVERFLOW)?;
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(entry);
    }
    Ok(bytes)
}

/// Decodes a helper configuration from its sealed descriptor.
pub(crate) fn read(descriptor: &FileDescriptor) -> Result<HelperConfig, Errno> {
    let mut header = [0u8; 8];
    descriptor.read_exact(&mut header)?;
    let flags = u16::from_le_bytes([header[0], header[1]]);
    let environment_count = usize::from(u16::from_le_bytes([header[2], header[3]]));
    let cwd_len = u32::from_le_bytes(header[4..8].try_into().expect("four bytes")) as usize;
    let known =
        EXEC_CWD_PRESENT | EXEC_ENVIRONMENT_PRESENT | EXEC_INHERIT_DEFAULT_ENV | EXEC_CWD_ENTERED;
    let cwd_entered = flags & EXEC_CWD_ENTERED != 0;
    if flags & !known != 0
        || (cwd_entered && flags & EXEC_CWD_PRESENT != 0)
        || environment_count > crate::protocol::MAX_ENVIRONMENT
        || (flags & EXEC_CWD_PRESENT == 0 && cwd_len != 0)
        || (flags & EXEC_CWD_PRESENT != 0
            && !(1..=crate::protocol::MAX_ARGUMENT_BYTES).contains(&cwd_len))
        || (flags & EXEC_ENVIRONMENT_PRESENT == 0
            && (environment_count != 0 || flags & EXEC_INHERIT_DEFAULT_ENV != 0))
    {
        return Err(Errno::EINVAL);
    }
    let cwd = if cwd_len == 0 {
        None
    } else {
        let mut cwd = vec![0; cwd_len];
        descriptor.read_exact(&mut cwd)?;
        Some(cwd)
    };
    let mut environment = Vec::with_capacity(environment_count);
    for _ in 0..environment_count {
        let mut length = [0u8; 4];
        descriptor.read_exact(&mut length)?;
        let length = u32::from_le_bytes(length) as usize;
        if !(1..=crate::protocol::MAX_ARGUMENT_BYTES).contains(&length) {
            return Err(Errno::EINVAL);
        }
        let mut entry = vec![0; length];
        descriptor.read_exact(&mut entry)?;
        if entry.contains(&0) || entry.first() == Some(&b'=') || !entry.contains(&b'=') {
            return Err(Errno::EINVAL);
        }
        environment.push(entry);
    }
    Ok(HelperConfig {
        cwd,
        environment: (flags & EXEC_ENVIRONMENT_PRESENT != 0).then_some(environment),
        inherit_default_env: flags & EXEC_INHERIT_DEFAULT_ENV != 0,
        cwd_entered,
    })
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, Write};

    use super::*;

    fn execution() -> GuestExecPayload {
        GuestExecPayload {
            timeout_ms: 0,
            argv: vec![b"/bin/true".to_vec()],
            cwd: Some(b"/tmp".to_vec()),
            environment: Some(vec![b"EMPTY=".to_vec(), b"VALUE=space = value".to_vec()]),
            inherit_default_env: false,
        }
    }

    fn file_with(bytes: &[u8]) -> FileDescriptor {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(bytes).unwrap();
        file.rewind().unwrap();
        FileDescriptor::from_owned(file.into())
    }

    #[test]
    fn helper_configuration_round_trips_empty_exact_and_large_environments() {
        for environment in [
            Vec::new(),
            vec![b"EMPTY=".to_vec(), b"VALUE=space = value".to_vec()],
            (0..12)
                .map(|index| {
                    let mut entry = format!("KEY{index}=").into_bytes();
                    entry.extend(std::iter::repeat_n(b'x', 4000));
                    entry
                })
                .collect(),
        ] {
            let mut execution = execution();
            execution.environment = Some(environment.clone());
            let descriptor = create(&execution, false).unwrap();
            let decoded = read(&descriptor).unwrap();
            assert_eq!(decoded.cwd, execution.cwd);
            assert_eq!(decoded.environment, Some(environment));
            assert!(!decoded.cwd_entered);
        }
    }

    #[test]
    fn helper_configuration_marks_an_entered_directory_and_is_sealed() {
        let execution = execution();
        let descriptor = create(&execution, true).unwrap();
        assert_eq!(descriptor.is_sealed_immutable(), Ok(true));
        let decoded = read(&descriptor).unwrap();
        assert!(decoded.cwd_entered);
        assert_eq!(decoded.cwd, None);
    }

    #[test]
    fn helper_defensively_rejects_unknown_flags_and_malformed_environment() {
        for bytes in [
            {
                let mut bytes = Vec::new();
                bytes.extend_from_slice(&0x4000u16.to_le_bytes());
                bytes.extend_from_slice(&0u16.to_le_bytes());
                bytes.extend_from_slice(&0u32.to_le_bytes());
                bytes
            },
            {
                let mut bytes = Vec::new();
                bytes.extend_from_slice(&EXEC_ENVIRONMENT_PRESENT.to_le_bytes());
                bytes.extend_from_slice(&1u16.to_le_bytes());
                bytes.extend_from_slice(&0u32.to_le_bytes());
                bytes.extend_from_slice(&9u32.to_le_bytes());
                bytes.extend_from_slice(b"NO_EQUALS");
                bytes
            },
            {
                let mut bytes = Vec::new();
                bytes.extend_from_slice(&EXEC_ENVIRONMENT_PRESENT.to_le_bytes());
                bytes.extend_from_slice(&1u16.to_le_bytes());
                bytes.extend_from_slice(&0u32.to_le_bytes());
                bytes.extend_from_slice(&6u32.to_le_bytes());
                bytes.extend_from_slice(b"=value");
                bytes
            },
            {
                let mut bytes = Vec::new();
                bytes.extend_from_slice(&EXEC_CWD_ENTERED.to_le_bytes());
                bytes.extend_from_slice(&0u16.to_le_bytes());
                bytes.extend_from_slice(&1u32.to_le_bytes());
                bytes.push(b'/');
                bytes
            },
        ] {
            let descriptor = file_with(&bytes);
            assert!(read(&descriptor).is_err(), "{bytes:?}");
        }
    }
}
