#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "include/icmp.h"

const icmp_func_set icmp_func = {
    .new_echo_req = new_echo_request,
    .send = icmp_send,
    .recv = recv_ip_icmp,
    .strerror = icmp_strerror,
    .to_str_pretty = icmp_to_str_pretty,
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
        return "recieved ip frame with invalid checksum";
    case IcmpInvalidIcmpCksumErr:
        return "recieved icmp packet with invalid checksum";
    }
}

uint16_t in_cksum(const char *addr, int size) {
    int sum = 0;
    while ((size -= 2) >= 0) {
        sum += *(uint16_t *)addr;
        addr += 2;
    }
    if (size == -1) {
        sum += *(uint8_t *)addr;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

IcmpPacket *new_echo_request(uint16_t id, uint16_t sequence) {
    IcmpPacket *icm = malloc(sizeof(IcmpPacket));
    memset(icm, 0, sizeof(*icm));
    icm->h_type = ICMP_ECHO;
    icm->h_code = 0;
    icm->h_id = id;
    icm->h_seq = sequence;
    icm->h_cksum = 0;
    clock_gettime(CLOCK_MONOTONIC_RAW, (struct timespec *)&icm->ts_creation);
    icm->h_cksum = in_cksum((char *)icm, sizeof(*icm));
    return icm;
}

IcmpResult icmp_send(const IcmpPacket *self, int sockfd, const struct sockaddr_storage *addr) {
    if (sendto(sockfd, (void *)self, sizeof(*self), 0, (struct sockaddr *)addr, sizeof(*addr)) == -1) {
        return IcmpSendToErr;
    }
    return IcmpOk;
}

bool icmp_verify_checksum(IcmpPacket *self) {
    uint16_t save = self->h_cksum;
    self->h_cksum = 0;
    uint16_t cksum = in_cksum((char *)self, sizeof(*self));
    self->h_cksum = save;
    return save == cksum;
}

// TODO Move to separate library.
bool ip_verify_checksum(struct iphdr *ip) {
    uint16_t save = ip->check;
    ip->check = 0;
    uint16_t cksum = in_cksum((char *)ip, ip->ihl * sizeof(int32_t));
    ip->check = save;
    return save == cksum;
}

IcmpResult recv_ip_icmp(
    struct iphdr **ip, IcmpPacket **icm, int sockfd, char buf[], int buf_len,
    struct sockaddr_storage *addr, socklen_t *addr_len
) {
    int recv_len = recvfrom(sockfd, buf, buf_len-1, 0, (struct sockaddr *)addr, addr_len);
    if (recv_len == -1) {
        // perror("recvfrom");
        return IcmpRecvFromErr;
    }

    *ip = (struct iphdr *)buf;
    struct iphdr *pip = (struct iphdr *)(*ip);
    if (ip_verify_checksum(*ip) == false) return IcmpInvalidIpCksumErr;
    pip->tot_len = ntohs(pip->tot_len);
    pip->id = ntohs(pip->id);
    pip->frag_off = ntohs(pip->frag_off);

    *icm = (struct IcmpPacket *)(buf + pip->ihl * sizeof(int32_t));
    IcmpPacket *picm = (struct IcmpPacket *)(*icm);
    // If we're pinging localhost, we'll receive our message too, so filter them out.
    if (picm->h_type == ICMP_ECHO) return recv_ip_icmp(ip, icm, sockfd, buf, buf_len, addr, addr_len);
    if (icmp_verify_checksum(picm) == false) return IcmpInvalidIcmpCksumErr;

    picm->h_id = ntohs(picm->h_id);
    picm->h_seq = ntohs(picm->h_seq);
    return IcmpOk;
}

const char *icmp_to_str_pretty(const IcmpPacket *self) {
    char *str = NULL;
    if (asprintf(&str, 
        "Type: %d\n"
        "Code: %d\n"
        "Checksum: %d\n"
        "Id: %d\n"
        "Seq: %d\n",
        self->h_type,
        self->h_code,
        self->h_cksum,
        self->h_id,
        self->h_seq
    ) == -1) {
        fprintf(stderr, "critical error while calling asprintf\n");
        exit(1);
    };
    return str;
}
