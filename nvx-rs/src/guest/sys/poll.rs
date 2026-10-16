//! Safe readiness polling for owned descriptors.

use nix::poll::{PollFd, PollFlags, poll};

use super::{Errno, FileDescriptor};

/// Polls up to three descriptors for readable data or hangup.
///
/// `None` entries are omitted, and the returned booleans preserve the caller's three positions.
/// Any reported event wakes that position, matching the C agent's `revents != 0` test.
pub(crate) fn readable_or_hung_up(
    descriptors: [Option<&FileDescriptor>; 3],
    timeout_milliseconds: u16,
) -> Result<[bool; 3], Errno> {
    let mut positions = Vec::with_capacity(descriptors.len());
    let mut polls = Vec::with_capacity(descriptors.len());
    for (position, descriptor) in descriptors.into_iter().enumerate() {
        if let Some(descriptor) = descriptor {
            positions.push(position);
            polls.push(PollFd::new(
                descriptor.borrowed(),
                PollFlags::POLLIN | PollFlags::POLLHUP,
            ));
        }
    }
    poll(&mut polls, timeout_milliseconds)?;
    let mut ready = [false; 3];
    for (position, descriptor) in positions.into_iter().zip(polls) {
        ready[position] = descriptor
            .revents()
            .is_some_and(|events| !events.is_empty());
    }
    Ok(ready)
}
