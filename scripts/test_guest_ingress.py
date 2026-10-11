#!/usr/bin/env python3
"""Tests for the guest listener announcer, guest/common/nvx-ingress.c.

The helper's test mode runs synthetic snapshots of the kernel's socket tables
and socket diagnostics through the scans that a guest runs, so these tests
check what it announces without a guest or privileges.
"""

from __future__ import annotations

import ipaddress
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE = REPO_ROOT / "guest" / "common" / "nvx-ingress.c"

TCP = 6
UDP = 17
IPV4 = 1
IPV6 = 2
BOTH = IPV4 | IPV6
TCP_LISTEN = 0x0A
TCP_ESTABLISHED = 0x01
UDP_CONNECTED = 0x01
UDP_UNCONNECTED = 0x07
UDP_SETTLE_MS = 1000
# The helper's first source port, which its test mode excludes like its own.
OWN_PORT = 1023
TABLE_HEADER = (
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
    "retrnsmt   uid  timeout inode\n"
)
NETLINK_HEADER = struct.Struct("=IHHII")
SOCK_DIAG_BY_FAMILY = 20
NETLINK_DONE = 3
INET_DIAG_SKV6ONLY = 11
AF_INET6 = 10


def kernel_address(address: str) -> str:
    """Render an address as the kernel's socket tables print it on x86."""
    packed = ipaddress.ip_address(address).packed
    return "".join(
        f"{int.from_bytes(packed[offset : offset + 4], 'little'):08X}"
        for offset in range(0, len(packed), 4)
    )


@dataclass(frozen=True)
class Socket:
    protocol: int
    address: str
    port: int
    inode: int
    state: int
    peer: tuple[str, int] | None = None

    @property
    def ipv6(self) -> bool:
        return ipaddress.ip_address(self.address).version == 6

    @property
    def table(self) -> str:
        return ("tcp" if self.protocol == TCP else "udp") + ("6" if self.ipv6 else "")

    def line(self, index: int) -> str:
        remote, remote_port = self.peer or ("::" if self.ipv6 else "0.0.0.0", 0)
        return (
            f"{index:4}: {kernel_address(self.address)}:{self.port:04X} "
            f"{kernel_address(remote)}:{remote_port:04X} {self.state:02X} "
            "00000000:00000000 00:00000000 00000000     0        0 "
            f"{self.inode} 2 0000000000000000\n"
        )


def tcp_listener(address: str, port: int, inode: int = 1) -> Socket:
    return Socket(TCP, address, port, inode, TCP_LISTEN)


def udp_socket(
    address: str, port: int, inode: int, peer: tuple[str, int] | None = None
) -> Socket:
    state = UDP_UNCONNECTED if peer is None else UDP_CONNECTED
    return Socket(UDP, address, port, inode, state, peer)


def diag_listener(port: int, ipv6_only: bool, address: str = "::") -> bytes:
    """Encode a socket diagnostics message for an IPv6 TCP listener."""
    message = struct.pack("=BBBB", AF_INET6, TCP_LISTEN, 0, 0)
    message += struct.pack("!HH", port, 0)
    message += ipaddress.IPv6Address(address).packed + bytes(16)
    message += struct.pack("=III", 0, 0, 0) + struct.pack("=IIIII", 0, 0, 0, 0, 0)
    message += struct.pack("=HH", 5, INET_DIAG_SKV6ONLY) + bytes(
        (int(ipv6_only), 0, 0, 0)
    )
    return (
        NETLINK_HEADER.pack(
            NETLINK_HEADER.size + len(message), SOCK_DIAG_BY_FAMILY, 2, 1, 0
        )
        + message
    )


def diag_done() -> bytes:
    return NETLINK_HEADER.pack(NETLINK_HEADER.size + 4, NETLINK_DONE, 2, 1, 0) + bytes(
        4
    )


@dataclass(frozen=True)
class Snapshot:
    time_ms: int
    sockets: tuple[Socket, ...] = ()
    bindv6only: int | None = None
    diag: bytes | None = None

    def write(self, root: Path) -> None:
        (root / "net").mkdir(parents=True)
        for table in ("tcp", "tcp6", "udp", "udp6"):
            sockets = [socket for socket in self.sockets if socket.table == table]
            (root / "net" / table).write_text(
                TABLE_HEADER
                + "".join(socket.line(index) for index, socket in enumerate(sockets)),
                encoding="utf-8",
            )
        if self.bindv6only is not None:
            sysctl = root / "sys" / "net" / "ipv6"
            sysctl.mkdir(parents=True)
            (sysctl / "bindv6only").write_text(f"{self.bindv6only}\n", encoding="utf-8")
        if self.diag is not None:
            (root / "diag").write_bytes(self.diag)
        (root / "time").write_text(f"{self.time_ms}\n", encoding="utf-8")


@dataclass(frozen=True)
class Announcement:
    payload: bytes
    truncated: bool
    listeners: dict[tuple[int, int], int]
    order: tuple[tuple[int, int], ...]

    @classmethod
    def decode(cls, payload: bytes) -> Announcement:
        magic, version, flags, count = struct.unpack("!4sBBH", payload[:8])
        if magic != b"NVXL" or version != 1 or len(payload) != 8 + 4 * count:
            raise AssertionError(f"malformed announcement {payload.hex()}")
        entries = [
            struct.unpack("!BBH", payload[8 + 4 * index : 12 + 4 * index])
            for index in range(count)
        ]
        return cls(
            payload,
            bool(flags & 1),
            {(protocol, port): families for protocol, families, port in entries},
            tuple((protocol, port) for protocol, _families, port in entries),
        )


@unittest.skipUnless(sys.platform.startswith("linux"), "nvx-ingress builds on Linux")
class GuestIngressTests(unittest.TestCase):
    binary: Path
    directory: tempfile.TemporaryDirectory[str]

    @classmethod
    def setUpClass(cls) -> None:
        compiler = shutil.which("cc") or shutil.which("gcc")
        if compiler is None:
            raise unittest.SkipTest("a C compiler is unavailable")
        cls.directory = tempfile.TemporaryDirectory()
        cls.binary = Path(cls.directory.name) / "nvx-ingress"
        subprocess.run(
            [
                compiler,
                "-O1",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-o",
                str(cls.binary),
                str(SOURCE),
            ],
            check=True,
            capture_output=True,
            timeout=120,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.directory.cleanup()

    def announce(self, *snapshots: Snapshot) -> list[Announcement]:
        with tempfile.TemporaryDirectory() as temporary:
            for index, snapshot in enumerate(snapshots):
                snapshot.write(Path(temporary) / str(index))
            result = subprocess.run(
                [str(self.binary), "test", temporary],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual(
            [int(line.split()[0]) for line in lines],
            [snapshot.time_ms for snapshot in snapshots],
        )
        return [Announcement.decode(bytes.fromhex(line.split()[1])) for line in lines]

    def test_announcement_golden_vector(self):
        (announcement,) = self.announce(
            Snapshot(
                0,
                (tcp_listener("0.0.0.0", 8080), tcp_listener("fd00::a00:2", 8443)),
            )
        )
        self.assertEqual(announcement.payload.hex(), "4e56584c0100000206011f90060220fb")

    def test_only_listeners_reachable_through_the_gateway_are_announced(self):
        sockets = (
            tcp_listener("0.0.0.0", 8080),
            tcp_listener("192.0.2.2", 8081),
            tcp_listener("127.0.0.1", 8082),
            tcp_listener("127.0.0.53", 8083),
            tcp_listener("::", 8084),
            tcp_listener("fd00::a00:2", 8085),
            tcp_listener("::1", 8086),
            tcp_listener("fe80::1", 8087),
            tcp_listener("::ffff:127.0.0.1", 8088),
            tcp_listener("::ffff:192.0.2.2", 8089),
            # One port's IPv4 and IPv6 listeners merge their families.
            tcp_listener("0.0.0.0", 8090),
            tcp_listener("fd00::a00:2", 8090, inode=2),
            # Established connections are not listeners.
            Socket(TCP, "192.0.2.2", 8091, 3, TCP_ESTABLISHED, ("192.0.2.1", 40000)),
        )
        (announcement,) = self.announce(Snapshot(0, sockets))
        self.assertEqual(
            announcement.listeners,
            {
                (TCP, 8080): IPV4,
                (TCP, 8081): IPV4,
                (TCP, 8084): BOTH,
                (TCP, 8085): IPV6,
                (TCP, 8089): IPV4,
                (TCP, 8090): BOTH,
            },
        )
        self.assertFalse(announcement.truncated)

    def test_ipv6_only_tcp_listeners_follow_socket_diagnostics(self):
        sockets = tuple(
            tcp_listener("::", port, inode=port) for port in range(7001, 7006)
        )
        diag = (
            diag_listener(7001, ipv6_only=True)
            + diag_listener(7002, ipv6_only=False)
            # A port that IPv6-only and dual-stack sockets share takes IPv4.
            + diag_listener(7003, ipv6_only=True)
            + diag_listener(7003, ipv6_only=False)
            # Only listeners on the unspecified address are classified.
            + diag_listener(7004, ipv6_only=True, address="fd00::a00:2")
            + diag_done()
            # Messages after the end of the dump are ignored.
            + diag_listener(7005, ipv6_only=True)
        )
        default, ipv6_only_default = self.announce(
            Snapshot(0, sockets, diag=diag),
            Snapshot(100, sockets, bindv6only=1, diag=diag_listener(7002, False)),
        )
        self.assertEqual(
            default.listeners,
            {
                (TCP, 7001): IPV6,
                (TCP, 7002): BOTH,
                (TCP, 7003): BOTH,
                (TCP, 7004): BOTH,
                (TCP, 7005): BOTH,
            },
        )
        # Without diagnostics for a socket, net.ipv6.bindv6only decides.
        self.assertEqual(
            ipv6_only_default.listeners,
            {
                (TCP, 7001): IPV6,
                (TCP, 7002): BOTH,
                (TCP, 7003): IPV6,
                (TCP, 7004): IPV6,
                (TCP, 7005): IPV6,
            },
        )

    def test_malformed_socket_diagnostics_are_ignored(self):
        sockets = (tcp_listener("::", 7101),)
        valid = diag_listener(7101, ipv6_only=True)
        short_attribute = bytearray(valid)
        struct.pack_into("=H", short_attribute, NETLINK_HEADER.size + 72, 2)
        long_attribute = bytearray(valid)
        struct.pack_into("=H", long_attribute, NETLINK_HEADER.size + 72, 200)
        for name, diag in (
            ("garbage", bytes(range(37))),
            ("short header", NETLINK_HEADER.pack(8, SOCK_DIAG_BY_FAMILY, 0, 0, 0)),
            (
                "overlong message",
                NETLINK_HEADER.pack(4096, SOCK_DIAG_BY_FAMILY, 0, 0, 0),
            ),
            ("truncated message", valid[:40]),
            ("short attribute", bytes(short_attribute)),
            ("overlong attribute", bytes(long_attribute)),
        ):
            with self.subTest(name):
                (announcement,) = self.announce(Snapshot(0, sockets, diag=diag))
                self.assertEqual(announcement.listeners, {(TCP, 7101): BOTH})

    def test_udp_sockets_settle_before_they_are_announced(self):
        sockets = (
            udp_socket("0.0.0.0", 7201, 10),
            udp_socket("::", 7202, 11),
            # The helper's own source port is never announced.
            udp_socket("0.0.0.0", OWN_PORT, 12),
            # Nor is a UDP socket bound to loopback.
            udp_socket("127.0.0.1", 7203, 13),
        )
        announcements = self.announce(
            Snapshot(0, sockets),
            Snapshot(UDP_SETTLE_MS - 1, sockets),
            Snapshot(UDP_SETTLE_MS, sockets),
            Snapshot(UDP_SETTLE_MS + 100, sockets, bindv6only=1),
        )
        self.assertEqual(announcements[0].listeners, {})
        self.assertEqual(announcements[1].listeners, {})
        self.assertEqual(
            announcements[2].listeners, {(UDP, 7201): IPV4, (UDP, 7202): BOTH}
        )
        self.assertEqual(
            announcements[3].listeners, {(UDP, 7201): IPV4, (UDP, 7202): IPV6}
        )

    def test_udp_ports_follow_the_identity_of_their_sockets(self):
        server = udp_socket("0.0.0.0", 7301, 20)
        replacement = udp_socket("0.0.0.0", 7301, 21)
        connected = udp_socket("192.0.2.2", 7301, 21, ("198.51.100.7", 5353))
        client = udp_socket("192.0.2.2", 7301, 22, ("192.0.2.1", 53))
        timeline = (
            (0, (server,), None),
            (UDP_SETTLE_MS, (server,), IPV4),
            # Another socket on the port settles anew.
            (UDP_SETTLE_MS + 100, (replacement,), None),
            (2 * UDP_SETTLE_MS + 99, (replacement,), None),
            (2 * UDP_SETTLE_MS + 100, (replacement,), IPV4),
            # A server that connects its announced socket keeps the port.
            (2 * UDP_SETTLE_MS + 200, (connected,), IPV4),
            (5 * UDP_SETTLE_MS, (connected,), IPV4),
            # A connected client that reuses the port never takes it over.
            (5 * UDP_SETTLE_MS + 100, (client,), None),
            (9 * UDP_SETTLE_MS, (client,), None),
        )
        announcements = self.announce(
            *(Snapshot(time_ms, sockets) for time_ms, sockets, _ in timeline)
        )
        for (time_ms, _sockets, families), announcement in zip(
            timeline, announcements, strict=True
        ):
            with self.subTest(time_ms=time_ms):
                expected = {} if families is None else {(UDP, 7301): families}
                self.assertEqual(announcement.listeners, expected)

    def test_udp_ports_announce_the_families_of_their_sockets(self):
        ipv4 = udp_socket("0.0.0.0", 7401, 30)
        ipv6 = udp_socket("::", 7401, 31)
        ipv4_connected = udp_socket("192.0.2.2", 7401, 30, ("198.51.100.7", 4000))
        ipv6_connected = udp_socket("fd00::a00:2", 7401, 31, ("fd12::7", 4000))
        timeline = (
            (0, (ipv4, ipv6), None),
            (UDP_SETTLE_MS, (ipv4, ipv6), BOTH),
            (UDP_SETTLE_MS + 100, (ipv4_connected, ipv6), BOTH),
            (UDP_SETTLE_MS + 200, (ipv4_connected, ipv6_connected), BOTH),
            (UDP_SETTLE_MS + 300, (ipv6_connected,), IPV6),
            (UDP_SETTLE_MS + 400, (), None),
        )
        announcements = self.announce(
            *(
                Snapshot(time_ms, sockets, bindv6only=1)
                for time_ms, sockets, _ in timeline
            )
        )
        for (time_ms, _sockets, families), announcement in zip(
            timeline, announcements, strict=True
        ):
            with self.subTest(time_ms=time_ms):
                expected = {} if families is None else {(UDP, 7401): families}
                self.assertEqual(announcement.listeners, expected)

    def test_announcements_carry_the_lowest_64_listeners(self):
        sockets = tuple(
            tcp_listener("0.0.0.0", port, inode=port) for port in range(2069, 1999, -1)
        )
        (announcement,) = self.announce(Snapshot(0, sockets))
        self.assertTrue(announcement.truncated)
        self.assertEqual(
            announcement.order, tuple((TCP, port) for port in range(2000, 2064))
        )
        (complete,) = self.announce(Snapshot(0, sockets[-64:]))
        self.assertFalse(complete.truncated)
        self.assertEqual(len(complete.order), 64)


if __name__ == "__main__":
    unittest.main()
