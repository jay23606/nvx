// nvx-ingress announces the guest's TCP and UDP listeners to the gateway of
// the portable network profile, which publishes them to the host's private
// networks. The init system starts it, as root, when the kernel command line
// carries virtnet_ingress=allow.
//
// Every 100 ms it reads the kernel's socket tables. A TCP socket in the LISTEN
// state is a listener, and so is an unconnected UDP socket that persists for a
// second, which skips short-lived client sockets, such as those of DNS queries.
// Each UDP socket settles on its own, identified by the kernel's inode for it,
// and stays announced while it exists, even once a server connects it to its
// client; another socket that reuses a port, such as a client's, settles anew,
// and a port announces the families of its announced sockets. Sockets bound to
// loopback addresses, or to IPv6 link-local ones, are unreachable through the
// gateway. A TCP listener on the unspecified IPv6 address also takes IPv4
// connections unless the kernel's socket diagnostics report it IPv6-only; a UDP
// socket there, which the guest kernel's diagnostics do not cover, follows
// net.ipv6.bindv6only. It sends the canonical set of listeners to UDP port 1021
// of the IPv4 gateway from a privileged port, which only root can bind,
// whenever the set changes and at least every 2 seconds.
//
// An announcement is the magic "NVXL", version 1, a flags byte whose bit 0
// marks omitted listeners, a big-endian count, and that many entries in
// increasing order of protocol and port: the IP protocol number, a family
// mask (1 for IPv4, 2 for IPv6), and the big-endian port.
//
// "nvx-ingress test DIRECTORY" runs the numbered snapshots in DIRECTORY, from
// 0, as successive scans instead, and prints each scan's time and
// announcement in hexadecimal. A snapshot holds the socket tables under net/,
// optionally sys/net/ipv6/bindv6only, optionally a socket diagnostics dump in
// diag, and the scan time in milliseconds in time.

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define ANNOUNCEMENT_PORT 1021
#define FIRST_SOURCE_PORT 1023
#define LAST_SOURCE_PORT 512
#define MAX_ANNOUNCED 64
#define MAX_TRACKED 1024
#define SCAN_INTERVAL_MS 100
#define REFRESH_INTERVAL_MS 2000
#define UDP_SETTLE_MS 1000
#define FAMILY_IPV4 1
#define FAMILY_IPV6 2
#define PROTOCOL_TCP 6
#define PROTOCOL_UDP 17
#define TCP_LISTEN 0x0a
#define UDP_CONNECTED 0x01
#define UDP_UNCONNECTED 0x07
#define HEADER_LENGTH 8
#define ENTRY_LENGTH 4

// The kernel's netlink socket diagnostics ABI (linux/netlink.h,
// linux/sock_diag.h, and linux/inet_diag.h), whose headers musl lacks.
#define NETLINK_SOCK_DIAG_PROTOCOL 4
#define NETLINK_REQUEST 0x01
#define NETLINK_DUMP 0x300
#define NETLINK_ERROR 2
#define NETLINK_DONE 3
#define SOCK_DIAG_BY_FAMILY 20
#define INET_DIAG_SKV6ONLY 11

struct netlink_header {
    uint32_t length;
    uint16_t type;
    uint16_t flags;
    uint32_t sequence;
    uint32_t pid;
};

struct netlink_address {
    sa_family_t family;
    unsigned short pad;
    uint32_t pid;
    uint32_t groups;
};

struct netlink_attribute {
    uint16_t length;
    uint16_t type;
};

struct inet_diag_socket_id {
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t source[4];
    uint32_t destination[4];
    uint32_t interface;
    uint32_t cookie[2];
};

struct inet_diag_request {
    uint8_t family;
    uint8_t protocol;
    uint8_t extensions;
    uint8_t pad;
    uint32_t states;
    struct inet_diag_socket_id id;
};

struct inet_diag_message {
    uint8_t family;
    uint8_t state;
    uint8_t timer;
    uint8_t retransmits;
    struct inet_diag_socket_id id;
    uint32_t expires;
    uint32_t receive_queue;
    uint32_t write_queue;
    uint32_t uid;
    uint32_t inode;
};

// Whether the IPv6 TCP listeners on the unspecified address at one port take
// IPv4 connections, as the kernel's socket diagnostics report them.
struct wildcard_listener {
    uint16_t port;
    uint8_t dual_stack;
    uint8_t ipv6_only;
};

struct listener {
    uint8_t protocol;
    uint8_t families;
    uint16_t port;
};

struct table {
    struct listener entries[MAX_TRACKED];
    size_t count;
};

// A reachable UDP socket, which the kernel's inode identifies while it exists.
struct udp_socket {
    uint16_t port;
    uint8_t families;
    uint8_t connected;
    unsigned long inode;
};

// A UDP socket that is settling or, once it has persisted unconnected for
// UDP_SETTLE_MS, announced.
struct udp_state {
    uint16_t port;
    uint8_t families;
    uint8_t announced;
    unsigned long inode;
    uint64_t first_seen_ms;
};

static struct table found;
static struct udp_socket udp_sockets[MAX_TRACKED];
static size_t udp_socket_count;
static struct udp_state udp_states[MAX_TRACKED];
static size_t udp_state_count;
static struct udp_state next_udp_states[MAX_TRACKED];
static uint8_t payload[HEADER_LENGTH + MAX_ANNOUNCED * ENTRY_LENGTH];
static uint8_t last_payload[sizeof(payload)];
static size_t last_length;
static int ipv6_dual_stack = 1;
static struct wildcard_listener wildcard_tcp[MAX_TRACKED];
static size_t wildcard_tcp_count;
static uint8_t diag_buffer[32768] __attribute__((aligned(8)));
// The root of the socket tables and sysctls, which test mode replaces.
static const char *proc_root = "/proc";
static int test_mode;

static uint64_t now_ms(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}

static void sleep_ms(unsigned int milliseconds)
{
    struct timespec delay = {
        .tv_sec = milliseconds / 1000,
        .tv_nsec = (long)(milliseconds % 1000) * 1000000,
    };
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
    }
}

// Records a listener, merging the address families of one protocol and port.
static void add(struct table *table, uint8_t protocol, uint16_t port, uint8_t families)
{
    for (size_t index = 0; index < table->count; ++index) {
        struct listener *entry = &table->entries[index];
        if (entry->protocol == protocol && entry->port == port) {
            entry->families |= families;
            return;
        }
    }
    if (table->count < MAX_TRACKED) {
        table->entries[table->count++] = (struct listener){
            .protocol = protocol,
            .families = families,
            .port = port,
        };
    }
}

// Returns the tracked state of the UDP socket with `inode` at `port`, if any.
static const struct udp_state *find_udp_state(uint16_t port, unsigned long inode)
{
    for (size_t index = 0; index < udp_state_count; ++index) {
        if (udp_states[index].port == port && udp_states[index].inode == inode) {
            return &udp_states[index];
        }
    }
    return NULL;
}

static int parse_hex_u32(const char *text, uint32_t *value)
{
    char digits[9];
    char *end;
    memcpy(digits, text, 8);
    digits[8] = '\0';
    errno = 0;
    unsigned long parsed = strtoul(digits, &end, 16);
    if (errno != 0 || *end != '\0' || end != digits + 8) {
        return 0;
    }
    *value = (uint32_t)parsed;
    return 1;
}

// Records the IPV6_V6ONLY state of an IPv6 TCP listener on the unspecified
// address from one socket diagnostics message.
static void note_wildcard_tcp(const uint8_t *message, size_t length)
{
    struct inet_diag_message diag;
    if (length < sizeof(diag)) {
        return;
    }
    memcpy(&diag, message, sizeof(diag));
    if (diag.family != AF_INET6 || diag.state != TCP_LISTEN) {
        return;
    }
    for (int word = 0; word < 4; ++word) {
        if (diag.id.source[word] != 0) {
            return;
        }
    }
    uint16_t port = ntohs(diag.id.source_port);
    for (size_t offset = sizeof(diag); offset + sizeof(struct netlink_attribute) <= length;) {
        struct netlink_attribute attribute;
        memcpy(&attribute, message + offset, sizeof(attribute));
        if (attribute.length < sizeof(attribute) || attribute.length > length - offset) {
            return;
        }
        if (attribute.type == INET_DIAG_SKV6ONLY && attribute.length > sizeof(attribute)) {
            uint8_t ipv6_only = message[offset + sizeof(attribute)] != 0;
            struct wildcard_listener *entry = NULL;
            for (size_t index = 0; index < wildcard_tcp_count; ++index) {
                if (wildcard_tcp[index].port == port) {
                    entry = &wildcard_tcp[index];
                }
            }
            if (entry == NULL && wildcard_tcp_count < MAX_TRACKED) {
                entry = &wildcard_tcp[wildcard_tcp_count++];
                *entry = (struct wildcard_listener){.port = port};
            }
            if (entry != NULL) {
                entry->dual_stack |= (uint8_t)!ipv6_only;
                entry->ipv6_only |= ipv6_only;
            }
            return;
        }
        offset += (attribute.length + 3u) & ~3u;
    }
}

// Records the IPv6 TCP listeners on the unspecified address of one part of a
// socket diagnostics dump, returning 0 once the dump ends or is malformed.
static int parse_wildcard_tcp(const uint8_t *buffer, size_t length)
{
    for (size_t offset = 0; offset + sizeof(struct netlink_header) <= length;) {
        struct netlink_header header;
        memcpy(&header, buffer + offset, sizeof(header));
        if (header.length < sizeof(header) || header.length > length - offset ||
            header.type == NETLINK_DONE || header.type == NETLINK_ERROR) {
            return 0;
        }
        if (header.type == SOCK_DIAG_BY_FAMILY) {
            note_wildcard_tcp(buffer + offset + sizeof(header), header.length - sizeof(header));
        }
        offset += (header.length + 3u) & ~3u;
    }
    return 1;
}

// Asks the kernel's socket diagnostics, or in test mode the snapshot's dump,
// which IPv6 TCP listeners on the unspecified address are IPv6-only. Without
// an answer, none is known.
static void query_wildcard_tcp(void)
{
    wildcard_tcp_count = 0;
    if (test_mode) {
        char path[4096];
        if (snprintf(path, sizeof(path), "%s/diag", proc_root) >= (int)sizeof(path)) {
            return;
        }
        FILE *file = fopen(path, "rbe");
        if (file != NULL) {
            size_t length = fread(diag_buffer, 1, sizeof(diag_buffer), file);
            fclose(file);
            parse_wildcard_tcp(diag_buffer, length);
        }
        return;
    }
    int fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_SOCK_DIAG_PROTOCOL);
    if (fd < 0) {
        return;
    }
    // A dump that never ends must not stall the scans.
    struct timeval timeout = {.tv_usec = SCAN_INTERVAL_MS * 1000};
    struct {
        struct netlink_header header;
        struct inet_diag_request request;
    } query = {
        .header =
            {
                .length = sizeof(query),
                .type = SOCK_DIAG_BY_FAMILY,
                .flags = NETLINK_REQUEST | NETLINK_DUMP,
            },
        .request =
            {
                .family = AF_INET6,
                .protocol = IPPROTO_TCP,
                .states = 1u << TCP_LISTEN,
            },
    };
    struct netlink_address kernel = {.family = AF_NETLINK};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
        sendto(fd, &query, sizeof(query), 0, (struct sockaddr *)&kernel, sizeof(kernel)) !=
            (ssize_t)sizeof(query)) {
        close(fd);
        return;
    }
    for (;;) {
        ssize_t received = recv(fd, diag_buffer, sizeof(diag_buffer), 0);
        if (received <= 0 || !parse_wildcard_tcp(diag_buffer, (size_t)received)) {
            break;
        }
    }
    close(fd);
}

// Returns the families through which an IPv6 socket of `protocol` on the
// unspecified address at `port` is reachable.
static uint8_t wildcard_families(uint8_t protocol, uint16_t port)
{
    if (protocol == PROTOCOL_TCP) {
        for (size_t index = 0; index < wildcard_tcp_count; ++index) {
            const struct wildcard_listener *entry = &wildcard_tcp[index];
            if (entry->port == port && (entry->dual_stack || entry->ipv6_only)) {
                return entry->dual_stack ? FAMILY_IPV4 | FAMILY_IPV6 : FAMILY_IPV6;
            }
        }
    }
    return ipv6_dual_stack ? FAMILY_IPV4 | FAMILY_IPV6 : FAMILY_IPV6;
}

// Returns the families through which a socket of `protocol` at `port`, bound
// to the kernel's hexadecimal rendering of an address, is reachable from the
// gateway, or 0. The kernel prints each 32-bit word of the address as it lies
// in memory.
static uint8_t reachable_families(const char *address, int ipv6, uint8_t protocol, uint16_t port)
{
    if (!ipv6) {
        struct in_addr ipv4;
        if (strlen(address) != 8 || !parse_hex_u32(address, &ipv4.s_addr)) {
            return 0;
        }
        return (ntohl(ipv4.s_addr) >> 24) == 127 ? 0 : FAMILY_IPV4;
    }
    struct in6_addr ipv6_address;
    if (strlen(address) != 32) {
        return 0;
    }
    for (int word = 0; word < 4; ++word) {
        uint32_t value;
        if (!parse_hex_u32(address + word * 8, &value)) {
            return 0;
        }
        memcpy(&ipv6_address.s6_addr[word * 4], &value, sizeof(value));
    }
    if (IN6_IS_ADDR_UNSPECIFIED(&ipv6_address)) {
        return wildcard_families(protocol, port);
    }
    if (IN6_IS_ADDR_LOOPBACK(&ipv6_address) || IN6_IS_ADDR_LINKLOCAL(&ipv6_address)) {
        return 0;
    }
    if (IN6_IS_ADDR_V4MAPPED(&ipv6_address)) {
        return ipv6_address.s6_addr[12] == 127 ? 0 : FAMILY_IPV4;
    }
    return FAMILY_IPV6;
}

// Adds the TCP listeners of one of the kernel's socket tables, `name` under
// net/, to `found`, and its reachable UDP sockets, connected or not, to
// `udp_sockets`.
static void scan(const char *name, uint8_t protocol, int ipv6, uint16_t own_port)
{
    char line[512];
    char path[4096];
    if (snprintf(path, sizeof(path), "%s/net/%s", proc_root, name) >= (int)sizeof(path)) {
        return;
    }
    FILE *file = fopen(path, "re");
    if (file == NULL) {
        return;
    }
    if (fgets(line, sizeof(line), file) == NULL) {
        fclose(file);
        return;
    }
    while (fgets(line, sizeof(line), file) != NULL) {
        char local[64];
        char remote[64];
        unsigned int state;
        unsigned long inode;
        if (sscanf(line, " %*u: %63s %63s %x %*s %*s %*s %*u %*u %lu", local, remote, &state,
                   &inode) != 4) {
            continue;
        }
        char *local_port = strrchr(local, ':');
        char *remote_port = strrchr(remote, ':');
        if (local_port == NULL || remote_port == NULL) {
            continue;
        }
        *local_port++ = '\0';
        *remote_port++ = '\0';
        unsigned long port = strtoul(local_port, NULL, 16);
        if (port == 0 || port > UINT16_MAX) {
            continue;
        }
        uint8_t connected = 0;
        if (protocol == PROTOCOL_TCP) {
            if (state != TCP_LISTEN) {
                continue;
            }
        } else if (state == UDP_CONNECTED) {
            connected = 1;
        } else if (state != UDP_UNCONNECTED || strtoul(remote_port, NULL, 16) != 0 ||
                   strspn(remote, "0") != strlen(remote) || port == own_port) {
            continue;
        }
        uint8_t families = reachable_families(local, ipv6, protocol, (uint16_t)port);
        if (families == 0) {
            continue;
        }
        if (protocol == PROTOCOL_TCP) {
            add(&found, protocol, (uint16_t)port, families);
        } else if (udp_socket_count < MAX_TRACKED) {
            udp_sockets[udp_socket_count++] = (struct udp_socket){
                .port = (uint16_t)port,
                .families = families,
                .connected = connected,
                .inode = inode,
            };
        }
    }
    fclose(file);
}

static int compare_listeners(const void *left, const void *right)
{
    const struct listener *a = left;
    const struct listener *b = right;
    if (a->protocol != b->protocol) {
        return a->protocol < b->protocol ? -1 : 1;
    }
    return a->port < b->port ? -1 : a->port > b->port;
}

// Scans the socket tables and encodes the announcement into `payload`,
// returning its length.
static size_t collect(uint16_t own_port, uint64_t now)
{
    found.count = 0;
    udp_socket_count = 0;
    query_wildcard_tcp();
    scan("tcp", PROTOCOL_TCP, 0, own_port);
    scan("tcp6", PROTOCOL_TCP, 1, own_port);
    scan("udp", PROTOCOL_UDP, 0, own_port);
    scan("udp6", PROTOCOL_UDP, 1, own_port);

    // An unconnected UDP socket is announced once it persists for
    // UDP_SETTLE_MS, and stays announced, even once a server connects it to a
    // client, while it exists. Each port announces the families of its
    // announced sockets.
    size_t next_count = 0;
    for (size_t index = 0; index < udp_socket_count; ++index) {
        const struct udp_socket *socket = &udp_sockets[index];
        const struct udp_state *previous = find_udp_state(socket->port, socket->inode);
        struct udp_state next = {
            .port = socket->port,
            .families = socket->families,
            .inode = socket->inode,
            .first_seen_ms = previous != NULL ? previous->first_seen_ms : now,
        };
        if (previous != NULL && previous->announced) {
            next.announced = 1;
        } else if (socket->connected) {
            continue;
        } else {
            next.announced = now - next.first_seen_ms >= UDP_SETTLE_MS;
        }
        next_udp_states[next_count++] = next;
        if (next.announced) {
            add(&found, PROTOCOL_UDP, next.port, next.families);
        }
    }
    memcpy(udp_states, next_udp_states, next_count * sizeof(udp_states[0]));
    udp_state_count = next_count;
    size_t announced = found.count;

    qsort(found.entries, announced, sizeof(found.entries[0]), compare_listeners);
    size_t count = announced < MAX_ANNOUNCED ? announced : MAX_ANNOUNCED;
    memcpy(payload, "NVXL", 4);
    payload[4] = 1;
    payload[5] = announced > MAX_ANNOUNCED;
    payload[6] = (uint8_t)(count >> 8);
    payload[7] = (uint8_t)count;
    for (size_t index = 0; index < count; ++index) {
        uint8_t *entry = &payload[HEADER_LENGTH + index * ENTRY_LENGTH];
        entry[0] = found.entries[index].protocol;
        entry[1] = found.entries[index].families;
        entry[2] = (uint8_t)(found.entries[index].port >> 8);
        entry[3] = (uint8_t)found.entries[index].port;
    }
    return HEADER_LENGTH + count * ENTRY_LENGTH;
}

static void read_bindv6only(void)
{
    char path[4096];
    if (snprintf(path, sizeof(path), "%s/sys/net/ipv6/bindv6only", proc_root) >=
        (int)sizeof(path)) {
        return;
    }
    FILE *file = fopen(path, "re");
    if (file == NULL) {
        return;
    }
    int value;
    if (fscanf(file, "%d", &value) == 1) {
        ipv6_dual_stack = value == 0;
    }
    fclose(file);
}

// Runs the snapshots in `directory` as successive scans; see the top of the
// file.
static int run_test(const char *directory)
{
    static char root[4096];
    test_mode = 1;
    for (unsigned int index = 0;; ++index) {
        char path[4200];
        if (snprintf(root, sizeof(root), "%s/%u", directory, index) >= (int)sizeof(root) ||
            snprintf(path, sizeof(path), "%s/time", root) >= (int)sizeof(path)) {
            return 1;
        }
        FILE *file = fopen(path, "re");
        if (file == NULL) {
            return index == 0;
        }
        unsigned long long now;
        int parsed = fscanf(file, "%llu", &now);
        fclose(file);
        if (parsed != 1) {
            return 1;
        }
        proc_root = root;
        ipv6_dual_stack = 1;
        read_bindv6only();
        size_t length = collect(FIRST_SOURCE_PORT, now);
        printf("%llu ", now);
        for (size_t offset = 0; offset < length; ++offset) {
            printf("%02x", payload[offset]);
        }
        printf("\n");
    }
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "test") == 0) {
        return run_test(argv[2]);
    }
    struct sockaddr_in gateway = {
        .sin_family = AF_INET,
        .sin_port = htons(ANNOUNCEMENT_PORT),
    };
    if (argc != 2 || inet_pton(AF_INET, argv[1], &gateway.sin_addr) != 1) {
        fprintf(stderr, "usage: nvx-ingress GATEWAY_IPV4\n");
        return 2;
    }
    signal(SIGINT, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    read_bindv6only();

    int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sock < 0) {
        fprintf(stderr, "nvx-ingress: socket: %s\n", strerror(errno));
        return 1;
    }
    uint16_t own_port = 0;
    for (int port = FIRST_SOURCE_PORT; port >= LAST_SOURCE_PORT && own_port == 0; --port) {
        struct sockaddr_in source = {
            .sin_family = AF_INET,
            .sin_port = htons((uint16_t)port),
            .sin_addr.s_addr = htonl(INADDR_ANY),
        };
        if (bind(sock, (struct sockaddr *)&source, sizeof(source)) == 0) {
            own_port = (uint16_t)port;
        } else if (errno != EADDRINUSE) {
            fprintf(stderr, "nvx-ingress: bind privileged port: %s\n", strerror(errno));
            return 1;
        }
    }
    if (own_port == 0) {
        fprintf(stderr, "nvx-ingress: no privileged source port is free\n");
        return 1;
    }

    uint64_t last_sent = 0;
    for (;;) {
        uint64_t now = now_ms();
        size_t length = collect(own_port, now);
        if (length != last_length || memcmp(payload, last_payload, length) != 0 ||
            now - last_sent >= REFRESH_INTERVAL_MS) {
            if (sendto(sock, payload, length, 0, (struct sockaddr *)&gateway,
                       sizeof(gateway)) == (ssize_t)length) {
                memcpy(last_payload, payload, length);
                last_length = length;
                last_sent = now;
            }
        }
        sleep_ms(SCAN_INTERVAL_MS);
    }
}
