#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "include/icmp.h"

const icmp_func_set icmp_func = {
    .new_echo4_req = new_echo4_request,
    .new_echo6_req = new_echo6_request,
    .send = icmp_send,
    .recv4 = recv_ip4_icmp,
    .recv6 = recv_ip6_icmp,
    .strerror = icmp_strerror,
};

const char *icmp_strerror(IcmpResult res) {
    switch (res) {
    case IcmpOk:
        return "";
    case IcmpSendToErr:
        return "error while sending message to the socket";
    case IcmpRecvFromErr:
        return "error while receiving message from the socket";
    case IcmpInvalidIpCksumErr:
        return "received ip frame with invalid checksum";
    case IcmpInvalidIcmpCksumErr:
        return "received icmp packet with invalid checksum";
    }
}

/// IcmpV6 Pseudo Header according to https://en.wikipedia.org/wiki/ICMPv6#Checksum
typedef struct Icmp6PseudoHeader {
    struct in6_addr src;
    struct in6_addr dest;
    // IcmpV6 packet length
    uint length;
    // Zeros
    const uint8_t _padding[3];
    // Always 58
    const uint8_t header;
} Icmp6PseudoHeader;

Icmp6PseudoHeader new_pseudo_header(struct in6_addr src, struct in6_addr dest, uint length) {
    Icmp6PseudoHeader ph = {
        .src = src,
        .dest = dest,
        .length = length,
        ._padding = {0, 0, 0},
        .header = 58
    };
    return ph;
}

uint16_t in_cksum(const char *addr, size_t size, uint16_t start) {
    int sum = start;
    while (size >= 2) {
        sum += *(uint16_t *)addr;
        addr += 2;
        size -= 2;
    }
    if (size == 1) {
        sum += *(uint8_t *)addr;
    }
    const int uint16_mask = 0xffff;
    sum = (sum >> 16) + (sum & uint16_mask);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

IcmpPacket *new_echo_default(uint16_t id, uint16_t seq) {
    IcmpPacket *icm = malloc(sizeof(IcmpPacket));
    memset(icm, 0, sizeof(*icm));
    icm->h_id = htons(id);
    icm->h_seq = htons(seq);
    clock_gettime(CLOCK_MONOTONIC_RAW, &icm->ts_creation);
    return icm;
}

IcmpPacket *new_echo4_request(uint16_t id, uint16_t seq) {
    IcmpPacket *icm = new_echo_default(id, seq);
    icm->h_type = ICMP_ECHO;
    icm->h_cksum = in_cksum((char *)icm, sizeof(*icm), 0);
    return icm;
}

IcmpPacket *new_echo6_request(struct in6_addr src, struct in6_addr dest, uint16_t id, uint16_t seq) {
    IcmpPacket *icm = new_echo_default(id, seq);
    icm->h_type = ICMP6_ECHO_REQUEST;
    Icmp6PseudoHeader ph = new_pseudo_header(src, dest, sizeof(*icm));
    icm->h_cksum = in_cksum((char *)icm, sizeof(*icm), in_cksum((char *)&ph, sizeof(ph), 0));
    return icm;
}

IcmpResult icmp_send(const IcmpPacket *self, int sockfd, const struct sockaddr_storage *addr) {
    if (sendto(sockfd, (void *)self, sizeof(*self), 0, (struct sockaddr *)addr, sizeof(*addr)) == -1) {
        return IcmpSendToErr;
    }
    return IcmpOk;
}

bool icmp_verify_checksum(IcmpPacket *self, const Icmp6PseudoHeader *const pseudo) {
    uint16_t save = self->h_cksum;
    self->h_cksum = 0;
    uint16_t start = (pseudo == NULL ? 0 : in_cksum((char *)pseudo, sizeof(*pseudo), 0));
    uint16_t cksum = in_cksum((char *)self, sizeof(*self), start);
    self->h_cksum = save;
    return save == cksum;
}

// TODO Move to separate library.
bool ip_verify_checksum(struct iphdr *ip) {
    uint16_t save = ip->check;
    ip->check = 0;
    uint16_t cksum = in_cksum((char *)ip, ip->ihl * sizeof(int32_t), 0);
    ip->check = save;
    return save == cksum;
}

IcmpResult recv_ip4_icmp(
    struct iphdr **ip, IcmpPacket **icm, int sockfd, u_char buf[], int buf_len,
    struct sockaddr_storage *addr, socklen_t *addr_len
) {
    size_t recv_len = recvfrom(sockfd, buf, buf_len, 0, (struct sockaddr *)addr, addr_len);
    if (recv_len == -1) {
        // perror("recvfrom");
        return IcmpRecvFromErr;
    }

    *ip = (struct iphdr *)buf;
    struct iphdr *pip = *ip;
    if (ip_verify_checksum(*ip) == false) return IcmpInvalidIpCksumErr;
    pip->tot_len = ntohs(pip->tot_len);
    pip->id = ntohs(pip->id);
    pip->frag_off = ntohs(pip->frag_off);

    *icm = (struct IcmpPacket *)(buf + pip->ihl * sizeof(int32_t));
    IcmpPacket *picm = (struct IcmpPacket *)(*icm);
    // If we're pinging localhost, we'll receive our message too, so filter them out.
    if (picm->h_type == ICMP_ECHO) {
        return recv_ip4_icmp(ip, icm, sockfd, buf, buf_len, addr, addr_len);
    }
    if (icmp_verify_checksum(picm, NULL) == false) return IcmpInvalidIcmpCksumErr;

    picm->h_id = ntohs(picm->h_id);
    picm->h_seq = ntohs(picm->h_seq);
    return IcmpOk;
}

IcmpResult recv_ip6_icmp(
    IcmpPacket **icm, int sockfd, u_char buf[], int buf_len,
    struct sockaddr_storage *addr, socklen_t *addr_len
) {
    size_t recv_len = recvfrom(sockfd, buf, buf_len, 0, (struct sockaddr *)addr, addr_len);
    if (recv_len == -1) {
        // perror("recvfrom");
        return IcmpRecvFromErr;
    }

    *icm = (struct IcmpPacket *)buf;
    IcmpPacket *picm = (struct IcmpPacket *)(*icm);
    // If we're pinging localhost, we'll receive our message too, so filter them out.
    if (picm->h_type == ICMP6_ECHO_REQUEST) {
        return recv_ip6_icmp(icm, sockfd, buf, buf_len, addr, addr_len);
    }
    // TODO verify checksum
    // Icmp6PseudoHeader ph = new_pseudo_header((*ip)->ip6_src, (*ip)->ip6_dst, (*ip)->ip6_plen);
    // if (icmp_verify_checksum(picm, &ph) == false) return IcmpInvalidIcmpCksumErr;

    picm->h_id = ntohs(picm->h_id);
    picm->h_seq = ntohs(picm->h_seq);
    return IcmpOk;
}
