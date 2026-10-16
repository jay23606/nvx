//! Datagram sockets: connected and unconnected IPv4 UDP sockets.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsRawFd, OwnedFd};

use nix::sys::socket::{AddressFamily, MsgFlags, SockFlag, SockType, SockaddrIn};

use super::{Errno, FileDescriptor};

/// Creates a close-on-exec IPv4 UDP socket connected to `peer`.
///
/// Connecting fixes the destination of every `write` and the only source from which `read`
/// receives, as the `socket` and `connect` calls of `nvx-device-io`'s C program did.
pub(crate) fn connect_datagram(peer: SocketAddrV4) -> Result<FileDescriptor, Errno> {
    let socket = nix::sys::socket::socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC,
        None,
    )?;
    nix::sys::socket::connect(socket.as_raw_fd(), &SockaddrIn::from(peer))?;
    Ok(FileDescriptor::from_owned(socket))
}

/// An unconnected, close-on-exec IPv4 UDP socket, from which `nvx-ingress` sends its
/// announcements.
///
/// Dropping it closes the socket, which the C program left to its exit.
#[derive(Debug)]
pub(crate) struct UdpSocket(OwnedFd);

impl UdpSocket {
    /// Creates the socket.
    pub(crate) fn ipv4() -> Result<Self, Errno> {
        nix::sys::socket::socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .map(Self)
    }

    /// Binds the socket to `port` on every local IPv4 address.
    pub(crate) fn bind_any(&self, port: u16) -> Result<(), Errno> {
        nix::sys::socket::bind(
            self.0.as_raw_fd(),
            &SockaddrIn::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)),
        )
    }

    /// Sends `payload` to `peer` in one datagram, and returns the number of bytes sent.
    pub(crate) fn send_to(&self, peer: SocketAddrV4, payload: &[u8]) -> Result<usize, Errno> {
        nix::sys::socket::sendto(
            self.0.as_raw_fd(),
            payload,
            &SockaddrIn::from(peer),
            MsgFlags::empty(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unconnected_datagrams_bind_and_send_to_a_peer() {
        let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let std::net::SocketAddr::V4(peer) = server.local_addr().unwrap() else {
            panic!("an IPv4 server");
        };
        let client = UdpSocket::ipv4().unwrap();
        assert_eq!(client.bind_any(0), Ok(()));
        assert_eq!(client.bind_any(0), Err(Errno::EINVAL));
        assert_eq!(client.send_to(peer, b"announce"), Ok(8));
        let mut buffer = [0; 16];
        let (length, _) = server.recv_from(&mut buffer).unwrap();
        assert_eq!(&buffer[..length], b"announce");
    }

    #[test]
    fn a_used_port_is_eaddrinuse() {
        let used = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let port = used.local_addr().unwrap().port();
        assert_eq!(
            UdpSocket::ipv4().unwrap().bind_any(port),
            Err(Errno::EADDRINUSE)
        );
    }
}
