#include <arpa/inet.h>
#include <ctype.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "include/args.h"
#include "include/icmp.h"

// TODO
// better handling of timeout
// add ipv6 support

//Regular bold text
#define BYEL "\e[1;33m"
#define BBLU "\e[1;34m"
#define BWHT "\e[1;37m"
//Regular underline text
#define UREG "\e[4;m"
//Reset
#define CRESET "\e[0m"

#define TIMEOUT 5000

/// Generate string with char `ch` `len` times.
/// Need to manually `free` to release allocated string.
const char *gen_str(const char symb, size_t len) {
    char *str = malloc(len * sizeof(symb) + 1);
    str[len] = '\0';
    #pragma unroll
    while (len > 0) {
        str[--len] = symb;
    }
    return str;
}

static struct {
    uint sent;
    uint received;
    double t_min;
    double t_max;
    double t_sum;
} glb_state = {
    0, 0, 0, 0, 0
};

// Creates a new string with the specified ansi color code.
// Returns unchanged string if stdout is not a `tty` or the config option is false.
const char *const color(const char *str, const char *color) {
    if (Config.color == ClrNever) return str;
    if (Config.color == ClrAuto && isatty(STDOUT_FILENO) == false) return str;

    // Constructs new string as ColorCode->String->ResetColorCode->'\0'
    size_t color_len = strlen(color), str_len = strlen(str), reset_len = strlen(CRESET);
    size_t len = color_len + str_len + reset_len + 1;
    char *new_str = (char *)malloc(len);
    memcpy(new_str, color, color_len);
    memcpy(new_str + color_len, str, str_len);
    memcpy(new_str + color_len + str_len, CRESET, reset_len);
    new_str[len - 1] = '\0';
    return new_str;
}

void greeting() {
    const char *sep = color(gen_str('+', 5), BYEL);
    printf("%s %s %s\n", sep, color("Woojiq's utils", BBLU), sep);
    free((void *)sep);
}

void finish() {
    const char *sep = color(gen_str('-', 3), BWHT);
    printf("%s %s ping statistics %s\n", sep, Config.hostname, sep);
    float perc;
    if (glb_state.received) perc = (float)(glb_state.sent - glb_state.received) * 100 / glb_state.received;
    else if (glb_state.sent) perc = 100;
    else perc = 0;
    printf(
        "%i packets transmitted, %i packets received, %i%% packet loss\n",
        glb_state.sent, glb_state.received, (int)perc
    );
    if (glb_state.received) {
        double avg = glb_state.t_sum / glb_state.received;
        printf("round-trip min/avg/max = %.2f/%.2f/%.2f ms\n", glb_state.t_min, avg, glb_state.t_max);
    }
    free((void *)sep);
    exit(0);
}

void setup_sigaction() {
    struct sigaction act = {0};
    act.sa_handler = finish;
    if (sigaction(SIGINT, &act, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }
}

// Calculates time between `start` and `end` in milliseconds with precision.
double calc_time(const struct timespec *start, const struct timespec *end) {
    double time = 
        (end->tv_sec - start->tv_sec) * 1000 + 
        (double)(end->tv_nsec - start->tv_nsec) / 1000000;
    return time;
}

// Resolves host by name and creates raw socket for sending ICMP packets.
int get_icmp_socket(struct sockaddr_storage *addr, socklen_t *addr_len) {
    struct addrinfo hints, *addrinfo_list, *paddr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = (Config.ip == IPv4 ? AF_INET : (Config.ip == IPv6 ? AF_INET6 : AF_UNSPEC));
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_ICMP;

    int status;
    if ((status = getaddrinfo(Config.hostname, NULL, &hints, &addrinfo_list)) != 0) {
        fprintf(stderr, "ping: %s\n", gai_strerror(status));
        exit(1);
    }

    int sockfd = -1;
    for (paddr = addrinfo_list; paddr != NULL; paddr = addrinfo_list->ai_next) {
        sockfd = socket(paddr->ai_family, paddr->ai_socktype, paddr->ai_protocol);
        if (sockfd >= 0) break;
    }

    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }

    *addr_len = paddr->ai_addrlen;
    memcpy(addr, paddr->ai_addr, *addr_len);

    freeaddrinfo(addrinfo_list);
    return sockfd;
}

// Convert sockaddr (sockaddr_storage) to internet address.
void *get_in_addr(struct sockaddr *sa) {
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in*)sa)->sin_addr);
  } else {
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
  }
}

void pr_iphdr(const struct iphdr *ip, const sa_family_t af_family) {
    const char *sep = color(gen_str('=', 5), BWHT);
    // frag_off and type of service are skipped
    printf("\t%s IP Header %s\n", sep, sep);
    printf("\tVersion: %d\n", ip->version);
    printf("\tHeader Length: %d\n", ip->ihl);
    printf("\tTotal Length: %d\n", ntohs(ip->tot_len));
    printf("\tId: %d\n", ntohs(ip->id));
    printf("\tTime To Live: %d\n", ip->ttl);
    printf("\tProtocol: %d\n", ip->protocol);
    printf("\tChecksum (verified): %d\n", ntohs(ip->check));

    char str[INET6_ADDRSTRLEN];
    inet_ntop(af_family, &ip->saddr, str, sizeof(str));
    printf("\tSource IP: %s\n", str);
    inet_ntop(af_family, &ip->daddr, str, sizeof(str));
    printf("\tDestination IP: %s\n", str);

    free((void *)sep);
}

void pr_icmp(const IcmpPacket *icm) {
    const char *sep = color(gen_str('=', 5), BWHT);

    printf("\t%s ICMP Header %s\n", sep, sep);
    const char *str = icmp_func.to_str_pretty(icm);
    char *last = str;
    char *newline = NULL;
    while ((newline = strchr(last, '\n')) != NULL) {
        printf("\t%.*s", (newline - last) / sizeof(char) + 1, last);
        last = newline + 1;
    }

    free((void *)sep);
}

void add_time_to_stat(const double time) {
    // First packet special case
    if (glb_state.received == 1) {
        glb_state.t_min = glb_state.t_max = glb_state.t_sum = time;
    } else {
        glb_state.t_sum += time;
        if (time < glb_state.t_min) glb_state.t_min = time;
        else if (time > glb_state.t_max) glb_state.t_max = time;
    }
}

int main(int argc, char *argv[]) {
    parse_args(argc, argv);
    greeting();
    setup_sigaction();

    struct sockaddr_storage addr, from;
    socklen_t addr_len, from_len;
    int sockfd = get_icmp_socket(&addr, &addr_len);

    char dest_ip[INET6_ADDRSTRLEN];
    inet_ntop(addr.ss_family, get_in_addr((struct sockaddr *)&addr), dest_ip, sizeof(dest_ip));

    printf("PING %s (%s): %lu data bytes\n", Config.hostname, dest_ip, sizeof(IcmpPacket));

    char buf[1028] = {0};
    struct iphdr *ip;
    IcmpPacket *icm;
    uint16_t max_seq = Config.count == 0 ? UINT16_MAX : Config.count;
    for (uint16_t seq = 0; seq < max_seq; seq++) {
        if (seq) sleep(1);
        icm = icmp_func.new_echo_req((uint16_t)getpid(), seq);
        icmp_func.send(icm, sockfd, &addr);

        glb_state.sent ++;
        IcmpResult res = icmp_func.recv(&ip, &icm, sockfd, buf, sizeof(buf), &from, &from_len);
        if (res != 0) {
            printf("%s: %s\n", Config.bin, icmp_func.strerror(res));
            exit(1);
        }

        glb_state.received ++;
        struct timespec curr_time;
        clock_gettime(CLOCK_MONOTONIC_RAW, &curr_time);
        double time = calc_time(&icm->ts_creation, &curr_time);
        add_time_to_stat(time);
        printf(
            "%li bytes from %s: icmp_seq=%i time=%.3fms\n", 
            sizeof(*ip) + sizeof(*icm), color(dest_ip, UREG), icm->h_seq, time
        );
        // We can't parse Ethernet header since we do not use `AF_PACKET`. See `packet(7)`.
        if (Config.verbosity > 0) {
            pr_iphdr(ip, addr.ss_family);
            pr_icmp(icm);
            const char *sep = gen_str('=', 55);
            printf("%s\n", sep);
            free((void *)sep);
        }
    }
    finish();
    return 0;
}
