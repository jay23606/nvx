#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define CONTROL_PORT 65535
#define CONTROL_SOURCE_PORT 68
#define CONTROL_MESSAGE_SIZE 14
#define DIAG_BUFFER_SIZE (32U * 1024U)
#define REFRESH_INTERVAL 50
#define WITHDRAWAL_RETRY_LIMIT 3
#define NETLINK_SOCK_DIAG 4
#define SOCK_DIAG_BY_FAMILY 20
#define NVX_INET_DIAG_SKV6ONLY 11
#define NVX_TCP_LISTEN 10
#define NVX_NLM_F_REQUEST 1
#define NVX_NLM_F_ROOT 0x100
#define NVX_NLM_F_MATCH 0x200
#define NVX_NLM_F_DUMP (NVX_NLM_F_ROOT | NVX_NLM_F_MATCH)
#define NVX_NLM_F_DUMP_INTR 0x10
#define NVX_NLMSG_ERROR 2
#define NVX_NLMSG_DONE 3
#define NVX_NLMSG_ALIGN(length) (((length) + 3U) & ~3U)
#define NVX_NLMSG_HDRLEN NVX_NLMSG_ALIGN(sizeof(struct nvx_nlmsghdr))
#define NVX_NLMSG_LENGTH(length) ((length) + NVX_NLMSG_HDRLEN)
#define NVX_NLMSG_DATA(header) ((void *)((uint8_t *)(header) + NVX_NLMSG_HDRLEN))
#define NVX_NLMSG_PAYLOAD(header) ((header)->length - NVX_NLMSG_HDRLEN)
#define NVX_NLMSG_OK(header, remaining)                                      \
    ((remaining) >= (int)sizeof(struct nvx_nlmsghdr) &&                     \
     (header)->length >= sizeof(struct nvx_nlmsghdr) &&                     \
     (header)->length <= (uint32_t)(remaining))
#define NVX_NLMSG_NEXT(header, remaining)                                   \
    ((remaining) -= (int)NVX_NLMSG_ALIGN((header)->length),                 \
     (struct nvx_nlmsghdr *)((uint8_t *)(header) +                          \
                            NVX_NLMSG_ALIGN((header)->length)))
#define NVX_RTA_ALIGN(length) (((length) + 3U) & ~3U)
#define NVX_RTA_LENGTH(length)                                              \
    (NVX_RTA_ALIGN(sizeof(struct nvx_rtattr)) + (length))
#define NVX_RTA_DATA(attribute)                                             \
    ((void *)((uint8_t *)(attribute) + NVX_RTA_LENGTH(0)))
#define NVX_RTA_PAYLOAD(attribute)                                          \
    ((int)(attribute)->length - (int)NVX_RTA_LENGTH(0))
#define NVX_RTA_OK(attribute, remaining)                                    \
    ((remaining) >= (int)sizeof(struct nvx_rtattr) &&                       \
     (attribute)->length >= sizeof(struct nvx_rtattr) &&                    \
     (attribute)->length <= (uint16_t)(remaining))
#define NVX_RTA_NEXT(attribute, remaining)                                  \
    ((remaining) -= (int)NVX_RTA_ALIGN((attribute)->length),                \
     (struct nvx_rtattr *)((uint8_t *)(attribute) +                         \
                          NVX_RTA_ALIGN((attribute)->length)))

#define LISTENER_TCP4 (1U << 0)
#define LISTENER_UDP4 (1U << 1)
#define LISTENER_TCP6 (1U << 2)
#define LISTENER_UDP6 (1U << 3)

struct nvx_sockaddr_nl {
    sa_family_t family;
    uint16_t pad;
    uint32_t pid;
    uint32_t groups;
};

struct nvx_nlmsghdr {
    uint32_t length;
    uint16_t type;
    uint16_t flags;
    uint32_t sequence;
    uint32_t pid;
};

struct nvx_inet_diag_sockid {
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t source[4];
    uint32_t destination[4];
    uint32_t interface;
    uint32_t cookie[2];
};

struct nvx_inet_diag_request {
    uint8_t family;
    uint8_t protocol;
    uint8_t extensions;
    uint8_t pad;
    uint32_t states;
    struct nvx_inet_diag_sockid id;
};

struct nvx_inet_diag_message {
    uint8_t family;
    uint8_t state;
    uint8_t timer;
    uint8_t retransmissions;
    struct nvx_inet_diag_sockid id;
    uint32_t expires;
    uint32_t receive_queue;
    uint32_t write_queue;
    uint32_t uid;
    uint32_t inode;
};

struct nvx_nlmsg_error {
    int32_t error;
    struct nvx_nlmsghdr message;
};

struct nvx_rtattr {
    uint16_t length;
    uint16_t type;
};

_Static_assert(sizeof(struct nvx_sockaddr_nl) == 12, "sockaddr_nl ABI");
_Static_assert(sizeof(struct nvx_nlmsghdr) == 16, "nlmsghdr ABI");
_Static_assert(sizeof(struct nvx_inet_diag_sockid) == 48, "inet_diag_sockid ABI");
_Static_assert(sizeof(struct nvx_inet_diag_request) == 56, "inet_diag_req_v2 ABI");
_Static_assert(sizeof(struct nvx_inet_diag_message) == 72, "inet_diag_msg ABI");
_Static_assert(sizeof(struct nvx_nlmsg_error) == 20, "nlmsgerr ABI");

static int is_zero_address(
    const struct nvx_inet_diag_message *message,
    int family)
{
    if (family == AF_INET) {
        return message->id.source[0] == 0;
    }
    return message->id.source[0] == 0 &&
           message->id.source[1] == 0 &&
           message->id.source[2] == 0 &&
           message->id.source[3] == 0;
}

static int is_loopback_address(
    const struct nvx_inet_diag_message *message,
    int family)
{
    if (family == AF_INET) {
        return (ntohl(message->id.source[0]) >> 24) == 127U;
    }
    {
        struct in6_addr address;

        memcpy(&address, message->id.source, sizeof(address));
        return IN6_IS_ADDR_LOOPBACK(&address) ||
               (IN6_IS_ADDR_V4MAPPED(&address) && address.s6_addr[12] == 127U);
    }
}

static int is_ipv4_mapped(const struct nvx_inet_diag_message *message)
{
    struct in6_addr address;

    memcpy(&address, message->id.source, sizeof(address));
    return IN6_IS_ADDR_V4MAPPED(&address);
}

static int socket_ipv6_only(
    const struct nvx_nlmsghdr *header,
    const struct nvx_inet_diag_message *message)
{
    size_t message_length = NVX_NLMSG_ALIGN(sizeof(*message));
    uint32_t payload_length = NVX_NLMSG_PAYLOAD(header);
    int remaining;
    struct nvx_rtattr *attribute;

    if (payload_length < message_length) {
        return 1;
    }
    remaining = (int)(payload_length - message_length);
    for (attribute =
             (struct nvx_rtattr *)((uint8_t *)message + message_length);
         NVX_RTA_OK(attribute, remaining);
         attribute = NVX_RTA_NEXT(attribute, remaining)) {
        if (attribute->type == NVX_INET_DIAG_SKV6ONLY &&
            NVX_RTA_PAYLOAD(attribute) >= 1) {
            return *(const uint8_t *)NVX_RTA_DATA(attribute) != 0;
        }
    }
    return 1;
}

static int scan_sockets(
    int fd,
    int protocol,
    int family,
    uint8_t listeners[65536])
{
    static uint32_t sequence;
    struct {
        struct nvx_nlmsghdr header;
        struct nvx_inet_diag_request request;
    } query = {
        .header = {
            .length = NVX_NLMSG_LENGTH(sizeof(struct nvx_inet_diag_request)),
            .type = SOCK_DIAG_BY_FAMILY,
            .flags = NVX_NLM_F_REQUEST | NVX_NLM_F_DUMP,
            .sequence = ++sequence,
        },
        .request = {
            .family = (uint8_t)family,
            .protocol = (uint8_t)protocol,
            .states = protocol == IPPROTO_TCP ?
                          (1U << NVX_TCP_LISTEN) :
                          UINT32_MAX,
            .id = {
                .cookie = {UINT32_MAX, UINT32_MAX},
            },
        },
    };
    struct nvx_sockaddr_nl kernel = {
        .family = AF_NETLINK,
    };
    union {
        struct nvx_nlmsghdr alignment;
        uint8_t bytes[DIAG_BUFFER_SIZE];
    } buffer;

    if (sendto(
            fd,
            &query,
            query.header.length,
            0,
            (const struct sockaddr *)&kernel,
            sizeof(kernel)) != (ssize_t)query.header.length) {
        return -1;
    }
    for (;;) {
        ssize_t received;
        int remaining;
        struct nvx_nlmsghdr *header;

        do {
            received = recv(fd, buffer.bytes, sizeof(buffer.bytes), 0);
        } while (received < 0 && errno == EINTR);
        if (received <= 0 || received > INT_MAX) {
            return -1;
        }
        remaining = (int)received;
        for (header = (struct nvx_nlmsghdr *)buffer.bytes;
             NVX_NLMSG_OK(header, remaining);
             header = NVX_NLMSG_NEXT(header, remaining)) {
            const struct nvx_inet_diag_message *message;
            int listener_family;
            uint16_t port;
            uint8_t bit;

            if (header->sequence != query.header.sequence) {
                continue;
            }
            if (header->type == NVX_NLMSG_DONE) {
                if (NVX_NLMSG_PAYLOAD(header) >= sizeof(int32_t)) {
                    int32_t status;

                    memcpy(&status, NVX_NLMSG_DATA(header), sizeof(status));
                    if (status != 0) {
                        errno = status < 0 ? -status : status;
                        return -1;
                    }
                }
                if ((header->flags & NVX_NLM_F_DUMP_INTR) != 0) {
                    errno = EINTR;
                    return -1;
                }
                return 0;
            }
            if (header->type == NVX_NLMSG_ERROR) {
                const struct nvx_nlmsg_error *error;

                if (NVX_NLMSG_PAYLOAD(header) < sizeof(*error)) {
                    errno = EPROTO;
                    return -1;
                }
                error = NVX_NLMSG_DATA(header);
                if (error->error == 0) {
                    return 0;
                }
                errno = -error->error;
                return -1;
            }
            if (NVX_NLMSG_PAYLOAD(header) < sizeof(*message)) {
                errno = EPROTO;
                return -1;
            }
            message = NVX_NLMSG_DATA(header);
            port = ntohs(message->id.source_port);
            if (port == 0 ||
                (protocol == IPPROTO_UDP && message->id.destination_port != 0) ||
                is_loopback_address(message, family)) {
                continue;
            }
            listener_family =
                family == AF_INET6 && is_ipv4_mapped(message) ? AF_INET : family;
            bit = protocol == IPPROTO_TCP ?
                      (listener_family == AF_INET6 ? LISTENER_TCP6 :
                                                     LISTENER_TCP4) :
                      (listener_family == AF_INET6 ? LISTENER_UDP6 :
                                                     LISTENER_UDP4);
            listeners[port] |= bit;
            if (listener_family == AF_INET6 &&
                !socket_ipv6_only(header, message) &&
                is_zero_address(message, family)) {
                listeners[port] |=
                    protocol == IPPROTO_TCP ? LISTENER_TCP4 : LISTENER_UDP4;
            }
        }
        if (remaining != 0) {
            errno = EPROTO;
            return -1;
        }
    }
}

static int send_update(int fd, uint8_t action, uint8_t listener, uint16_t port)
{
    uint8_t message[CONTROL_MESSAGE_SIZE] = {
        'N', 'V', 'X', 'H', 'L', 'B', '1', '\0', action, 0, 0, 0, 0, 0,
    };
    ssize_t written;

    switch (listener) {
    case LISTENER_TCP4:
        message[9] = 1;
        message[10] = 4;
        break;
    case LISTENER_UDP4:
        message[9] = 2;
        message[10] = 4;
        break;
    case LISTENER_TCP6:
        message[9] = 1;
        message[10] = 6;
        break;
    case LISTENER_UDP6:
        message[9] = 2;
        message[10] = 6;
        break;
    default:
        return -1;
    }
    message[12] = (uint8_t)(port >> 8);
    message[13] = (uint8_t)port;
    do {
        written = send(fd, message, sizeof(message), 0);
    } while (written < 0 && errno == EINTR);
    return written == (ssize_t)sizeof(message) ? 0 : -1;
}

static void pause_before_scan(void)
{
    struct timespec delay = {
        .tv_sec = 0,
        .tv_nsec = 100 * 1000 * 1000,
    };

    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
    }
}

int main(int argc, char **argv)
{
    static uint8_t current[65536];
    static uint8_t observed[65536];
    static uint8_t withdrawal_attempts[4][65536];
    const uint8_t listener_bits[] = {
        LISTENER_TCP4,
        LISTENER_UDP4,
        LISTENER_TCP6,
        LISTENER_UDP6,
    };
    struct sockaddr_in gateway = {
        .sin_family = AF_INET,
        .sin_port = htons(CONTROL_PORT),
    };
    struct sockaddr_in source = {
        .sin_family = AF_INET,
        .sin_port = htons(CONTROL_SOURCE_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    unsigned int iteration = 0;
    int connect_warned = 0;
    int diag_fd;
    int fd;
    int scan_warned = 0;
    int warned = 0;

    if (argc != 2 || inet_pton(AF_INET, argv[1], &gateway.sin_addr) != 1) {
        fprintf(stderr, "usage: nvx-host-loopback-agent GATEWAY_IPV4\n");
        return 2;
    }
    for (;;) {
        fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (fd >= 0 && bind(fd, (const struct sockaddr *)&source, sizeof(source)) == 0 &&
            connect(fd, (const struct sockaddr *)&gateway, sizeof(gateway)) == 0) {
            break;
        }
        if (!connect_warned) {
            perror("nvx-host-loopback-agent: connect");
            connect_warned = 1;
        }
        if (fd >= 0) {
            close(fd);
        }
        pause_before_scan();
    }
    for (;;) {
        diag_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
        if (diag_fd >= 0) {
            break;
        }
        if (!scan_warned) {
            perror("nvx-host-loopback-agent: socket diagnostics");
            scan_warned = 1;
        }
        pause_before_scan();
    }
    scan_warned = 0;

    for (;;) {
        unsigned int port;

        memset(observed, 0, sizeof(observed));
        if (scan_sockets(diag_fd, IPPROTO_TCP, AF_INET, observed) != 0 ||
            scan_sockets(diag_fd, IPPROTO_UDP, AF_INET, observed) != 0 ||
            scan_sockets(diag_fd, IPPROTO_TCP, AF_INET6, observed) != 0 ||
            scan_sockets(diag_fd, IPPROTO_UDP, AF_INET6, observed) != 0) {
            if (!scan_warned) {
                perror("nvx-host-loopback-agent: scan");
                scan_warned = 1;
            }
            pause_before_scan();
            continue;
        }
        scan_warned = 0;

        for (port = 1; port <= UINT16_MAX; ++port) {
            size_t index;

            for (index = 0; index < sizeof(listener_bits); ++index) {
                uint8_t listener = listener_bits[index];
                uint8_t action = 0;
                uint8_t *attempts = &withdrawal_attempts[index][port];

                if ((observed[port] & listener) != 0) {
                    if ((current[port] & listener) == 0 || *attempts != 0 ||
                        iteration == REFRESH_INTERVAL) {
                        action = 1;
                    }
                    *attempts = 0;
                } else if ((current[port] & listener) != 0 &&
                           (*attempts == 0 ||
                            iteration == REFRESH_INTERVAL)) {
                    action = 2;
                }
                if (action == 0) {
                    continue;
                }
                if (send_update(fd, action, listener, (uint16_t)port) == 0) {
                    warned = 0;
                    if (action == 1) {
                        current[port] |= listener;
                    } else {
                        ++*attempts;
                        if (*attempts >= WITHDRAWAL_RETRY_LIMIT) {
                            current[port] &= (uint8_t)~listener;
                            *attempts = 0;
                        }
                    }
                } else if (!warned) {
                    perror("nvx-host-loopback-agent: publish");
                    warned = 1;
                }
            }
        }
        iteration = iteration == REFRESH_INTERVAL ? 0 : iteration + 1;
        pause_before_scan();
    }
}
