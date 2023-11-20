#ifndef PING_ICMP_H_
#define PING_ICMP_H_

#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <stdbool.h>

/// Returns IPv4 checksum according to RFC 1071.
uint16_t in_cksum(const char *addr, size_t size, uint16_t start);

/// Icmp header with payload section containing creation timestamp.
/// Fields are always in native byte order and are converted internally before sending/after receiving.
typedef struct IcmpPacket {
    struct icmphdr header;
#define h_type header.type
#define h_code header.code
#define h_cksum header.checksum
#define h_seq header.un.echo.sequence
#define h_id header.un.echo.id
    struct timespec ts_creation;
} IcmpPacket;

typedef enum IpVersion {
    IPv4 = 4,
    IPv6 = 6,
} IpVersion;

typedef enum IcmpResult {
    IcmpOk = 0,
    IcmpSendToErr = -1,
    IcmpRecvFromErr = -2,
    IcmpInvalidIpCksumErr = -3,
    IcmpInvalidIcmpCksumErr = -4,
} IcmpResult;

typedef struct icmp_func_set {
    IcmpPacket *(*new_echo4_req)(uint16_t, uint16_t);
    IcmpPacket *(*new_echo6_req)(struct in6_addr, struct in6_addr, uint16_t, uint16_t);
    IcmpResult (*send)(const IcmpPacket *, int, const struct sockaddr_storage *);
    IcmpResult (*recv4)(struct iphdr **, IcmpPacket **, int, u_char *, int, struct sockaddr_storage *, socklen_t *);
    IcmpResult (*recv6)(IcmpPacket **, int, u_char *, int, struct sockaddr_storage *, socklen_t *);
    const char *(*strerror)(IcmpResult);
    const char *(*to_str_pretty)(const IcmpPacket *);
} icmp_func_set;

extern const icmp_func_set icmp_func;

/// Return: Icmp Echo request struct base on IPv4 with timestamp in payload.
IcmpPacket *new_echo4_request(uint16_t id, uint16_t seq);

/// Return: Icmp Echo request struct based on IPv6 with timestamp in payload.
/// There is need for `src` and `dest` because they are used to calculate checksum.
IcmpPacket *new_echo6_request(struct in6_addr src, struct in6_addr dest, uint16_t id, uint16_t seq);

/// Send Icmp packet to socket with specified IP address.
/// Return: number of bytes sent, on error, -1 is returned, and errno is set.
IcmpResult icmp_send(const IcmpPacket *self, int sockfd, const struct sockaddr_storage *addr);

/// Recieve IPv4-ICMPv4 packet from socket (blocking) and verify checksum.
/// IPv4 and ICMPv4 packets are bounded to the `buf` lifetime.
IcmpResult recv_ip4_icmp(
    struct iphdr **ip, IcmpPacket **icm, int sockfd, u_char buf[], int buf_len,
    struct sockaddr_storage *addr, socklen_t *addr_len
);

/// Recieve IPv6-ICMPv6 packet from socket (blocking) and verify checksum.
/// IPv6 and ICMPv6 packets are bounded to the `buf` lifetime.
IcmpResult recv_ip6_icmp(
    IcmpPacket **icm, int sockfd, u_char buf[], int buf_len,
    struct sockaddr_storage *addr, socklen_t *addr_len
);

/// Return: string describing error number.
const char *icmp_strerror(IcmpResult res);

#endif
