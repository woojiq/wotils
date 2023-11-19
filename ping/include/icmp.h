#ifndef PING_ICMP_H_
#define PING_ICMP_H_

#include <netinet/ip_icmp.h>
#include <stdbool.h>

/// Returns IPv4 checksum according to RFC 1071.
uint16_t in_cksum(const char *addr, uint size);

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

typedef enum IcmpResult {
    IcmpOk = 0,
    IcmpSendToErr = -1,
    IcmpRecvFromErr = -2,
    IcmpInvalidIpCksumErr = -3,
    IcmpInvalidIcmpCksumErr = -4,
} IcmpResult;

typedef struct icmp_func_set {
    IcmpPacket *(*new_echo_req)(uint16_t, uint16_t);
    IcmpResult (*send)(const IcmpPacket *, int, const struct sockaddr_storage *);
    IcmpResult (*recv)(struct iphdr **, IcmpPacket **, int, char *, int, struct sockaddr_storage *, socklen_t *);
    const char *(*strerror)(IcmpResult);
    const char *(*to_str_pretty)(const IcmpPacket *);
} icmp_func_set;

extern const icmp_func_set icmp_func;

/// Return: Icmp Echo request struct with timestamp in payload.
IcmpPacket *new_echo_request(uint16_t id, uint16_t sequence);

/// Send Icmp packet to socket with specified IP address.
/// Return: number of bytes sent, on error, -1 is returned, and errno is set.
IcmpResult icmp_send(const IcmpPacket *self, int sockfd, const struct sockaddr_storage *addr);

/// Verify Icmp packet checksum.
bool icmp_verify_checksum(IcmpPacket *self);

/// Recieve Ip-Icmp packet from socket (blocking) and verify checksum.
/// Ip and Icmp packets are bounded to the `buf` lifetime.
IcmpResult recv_ip_icmp(
    struct iphdr **ip, IcmpPacket **icm, int sockfd, char buf[], int buf_len,
    struct sockaddr_storage *addr, socklen_t *addr_len
);

/// Return: string describing error number.
const char *icmp_strerror(IcmpResult res);

/// Return: pretty string header without timestamp.
const char *icmp_to_str_pretty(const IcmpPacket *self);

#endif
