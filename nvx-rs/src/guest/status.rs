//! Exit statuses and failures shared by the guest programs.

use std::process::ExitCode;

/// Process exit statuses of the guest programs.
///
/// A program exits with [`Success`](Self::Success), or with the status that its
/// [`CommandError`] selects. Only `nvx-device-io` exits with the benchmark statuses 3, 4, and
/// 255, and only `nvx-managed-agent` exits with 125.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum ExitStatus {
    /// The program completed.
    Success = 0,
    /// An operation failed.
    Failure = 1,
    /// The command line was invalid.
    Usage = 2,
    /// A benchmark could not open, connect, size, or time its device.
    SetupFailure = 3,
    /// A benchmark transfer or send was incomplete.
    TransferFailure = 4,
    /// The managed agent, or its execution helper before it executed the workload, failed.
    AgentFailure = 125,
    /// A benchmark could not write its result.
    OutputFailure = 255,
}

/// Typed failure of a guest program, which selects its exit status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommandError {
    /// The command line is invalid. A program with a usage message has printed it.
    Usage,
    /// An operation failed. A program that reports failures has printed why.
    Operation,
    /// A benchmark could not open, connect, size, or time its device.
    Setup,
    /// A benchmark transfer or send was incomplete.
    Transfer,
    /// A benchmark could not write its result.
    Output,
    /// The managed agent or its execution helper failed for any reason, including an invalid
    /// command line. It has reported why where its C program did.
    Agent,
}

impl From<Result<(), CommandError>> for ExitStatus {
    fn from(result: Result<(), CommandError>) -> Self {
        match result {
            Ok(()) => Self::Success,
            Err(CommandError::Usage) => Self::Usage,
            Err(CommandError::Operation) => Self::Failure,
            Err(CommandError::Setup) => Self::SetupFailure,
            Err(CommandError::Transfer) => Self::TransferFailure,
            Err(CommandError::Output) => Self::OutputFailure,
            Err(CommandError::Agent) => Self::AgentFailure,
        }
    }
}

impl From<ExitStatus> for ExitCode {
    fn from(status: ExitStatus) -> Self {
        Self::from(status as u8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failures_select_the_documented_statuses() {
        let cases = [
            (Ok(()), 0),
            (Err(CommandError::Operation), 1),
            (Err(CommandError::Usage), 2),
            (Err(CommandError::Setup), 3),
            (Err(CommandError::Transfer), 4),
            (Err(CommandError::Agent), 125),
            (Err(CommandError::Output), 255),
        ];
        for (result, code) in cases {
            assert_eq!(ExitStatus::from(result) as u8, code, "{result:?}");
        }
    }
}
