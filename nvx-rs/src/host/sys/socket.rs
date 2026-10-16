//! Unix stream connections to OpenVMM's control socket.

use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

use nix::sys::socket::sockopt::PeerCredentials;
use nix::sys::socket::{AddressFamily, SockFlag, SockType, UnixAddr, connect, getsockopt, socket};

use super::Errno;

/// Connects to the Unix socket at `path` without waiting in a full listen backlog, and returns
/// the connected stream in blocking mode.
///
/// A full backlog fails with [`io::ErrorKind::WouldBlock`], and a path that does not fit a Unix
/// socket address with [`io::ErrorKind::InvalidInput`].
pub(crate) fn connect_nonblocking(path: &str) -> io::Result<UnixStream> {
    let address = UnixAddr::new(path).map_err(|error| match error {
        Errno::ENAMETOOLONG => io::Error::new(
            io::ErrorKind::InvalidInput,
            "control socket path is too long",
        ),
        error => error.into(),
    })?;
    let socket = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )?;
    connect(socket.as_raw_fd(), &address)?;
    let stream = UnixStream::from(socket);
    stream.set_nonblocking(false)?;
    Ok(stream)
}

/// Returns the process ID of the peer credentials of a connected Unix stream.
pub(crate) fn peer_pid(stream: &UnixStream) -> io::Result<u32> {
    let credentials = getsockopt(stream, PeerCredentials)?;
    u32::try_from(credentials.pid()).map_err(io::Error::other)
}
