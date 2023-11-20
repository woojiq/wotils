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

//Regular bold text
#define BYEL "\e[1;33m"
#define BBLU "\e[1;34m"
#define BWHT "\e[1;37m"
//Regular underline text
#define UREG "\e[4;m"
//Reset
#define CRESET "\e[0m"

/// Generate string with char `ch` `len` times.
/// Need to manually `free` to release allocated string.
const char *gen_str(const char symb, size_t len) {
    char *str = malloc(len * sizeof(symb) + 1);
    str[len] = '\0';
    while (len > 0) {
        str[--len] = symb;
    }
    return str;
}

/// Global application state for statistics printed at the end of execution.
static struct {
    uint sent;
    uint received;
    double t_min;
    double t_max;
    double t_sum;
} glb_state = {
    0, 0, 0, 0, 0
};

/// Create a new string with the specified ansi color code.
/// `free` can be set to true to `free` passed string.
/// Return: new duplicate string if stdout is not a `tty` or the config option is false.
const char *color(const char *str, const char *color, bool to_free) {
    size_t str_len = strlen(str);
    if (
        config.color == ClrNever || 
        (config.color == ClrAuto && isatty(STDOUT_FILENO)) == false
    ) {
        char *new_str = (char *)malloc(str_len + 1);
        new_str[0] = '\0';
        strcat(new_str, str);
        if (to_free) free((void *)str);
        return new_str;
    }

    // Constructs new string as ColorCode->String->ResetColorCode->'\0'
    size_t color_len = strlen(color);
    size_t reset_len = strlen(CRESET);
    size_t len = color_len + str_len + reset_len + 1;

    char *new_str = (char *)malloc(len);
    memcpy(new_str, color, color_len);
    memcpy(new_str + color_len, str, str_len);
    memcpy(new_str + color_len + str_len, CRESET, reset_len);
    new_str[len - 1] = '\0';
    if (to_free) free((void *)str);
    return new_str;
}

/// Greeting message printed before main loop.
void greeting() {
    const char *sep = color(gen_str('+', 5), BYEL, true);
    const char *name = color("Woojiq's utils", BBLU, false);
    printf("%s %s %s\n", sep, name, sep);
    free((void *)sep);
    free((void *)name);
}

/// Print statistics stored in `glb_state`.
void finish() {
    const char *sep = color(gen_str('-', 3), BWHT, true);
    printf("%s %s ping statistics %s\n", sep, config.hostname, sep);
    float perc;
    if (glb_state.received) {
        perc = (float)(glb_state.sent - glb_state.received) * 100 / (float)glb_state.received;
    } else if (glb_state.sent) {
        perc = 100;
    } else {
        perc = 0;
    }
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

/// Calculate time between `start` and `end` in milliseconds with precision.
double calc_time(const struct timespec *start, const struct timespec *end) {
    #define MILLIS_IN_SEC (1000)
    #define NANOS_IN_MILLI (1000000)
    double time = 
        (double)(end->tv_sec - start->tv_sec) * MILLIS_IN_SEC + 
        (double)(end->tv_nsec - start->tv_nsec) / NANOS_IN_MILLI;
    return time;
}

/// Resolve host by name and creates raw socket for sending ICMP packets.
int get_icmp_socket(struct sockaddr_storage *addr, socklen_t *addr_len) {
    struct addrinfo hints, *addrinfo_list, *paddr;
    memset(&hints, 0, sizeof(hints));
    // There is no AF_UNSPEC equivalent for IPPROTO_ICMP, so we need to select version manually.
    if (config.ip == IPv4) {
        hints.ai_family = AF_INET;
        hints.ai_protocol = IPPROTO_ICMP;
    } else if (config.ip == IPv6) {
        hints.ai_family = AF_INET6;
        hints.ai_protocol = IPPROTO_ICMPV6;
    }
    hints.ai_socktype = SOCK_RAW;

    int status;
    if ((status = getaddrinfo(config.hostname, NULL, &hints, &addrinfo_list)) != 0) {
        (void)fprintf(stderr, "ping: %s\n", gai_strerror(status));
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

/// Convert sockaddr (sockaddr_storage) to internet address.
void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

/// Pretty-print IP header
void pr_iphdr(const struct iphdr *ip, const sa_family_t af) {
    const char *sep = color(gen_str('=', 5), BWHT, true);
    // frag_off and type of service are skipped
    printf("\t%s IPv4 Header %s\n", sep, sep);
    printf("\tVersion: %d\n", ip->version);
    printf("\tHeader Length: %d\n", ip->ihl);
    printf("\tTotal Length: %d\n", ntohs(ip->tot_len));
    printf("\tId: %d\n", ntohs(ip->id));
    printf("\tTime To Live: %d\n", ip->ttl);
    printf("\tProtocol: %d\n", ip->protocol);
    printf("\tChecksum (verified): %d\n", ntohs(ip->check));

    char str[INET_ADDRSTRLEN];
    inet_ntop(af, &ip->saddr, str, sizeof(str));
    printf("\tSource IP: %s\n", str);
    inet_ntop(af, &ip->daddr, str, sizeof(str));
    printf("\tDestination IP: %s\n", str);

    free((void *)sep);
}

/// Pretty-print ICMP header
void pr_icmp(const IcmpPacket *icm) {
    const char *sep = color(gen_str('=', 5), BWHT, true);

    printf("\t%s ICMP Header %s\n", sep, sep);
    printf("\tType: %d\n", icm->h_type);
    printf("\tCode: %d\n", icm->h_code);
    printf("\tChecksum: %d\n", icm->h_cksum);
    printf("\tId: %d\n", icm->h_id);
    printf("\tSeq: %d\n", icm->h_seq);

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

void process_ip4_response(
    const struct iphdr *ip4, const struct IcmpPacket *icm,
    const char *dest_str, sa_family_t fam,
    double time
) {
    printf(
        "%li bytes from %s: icmp_seq=%i time=%.3fms\n", 
        sizeof(*ip4) + sizeof(*icm), dest_str, icm->h_seq, time
    );
    // We can't parse Ethernet header since we do not use `AF_PACKET`. See `packet(7)`.
    if (config.verbosity > 0) {
        pr_iphdr(ip4, fam);
        pr_icmp(icm);
        const char *sep = gen_str('=', 55);
        printf("%s\n", sep);
        free((void *)sep);
    }
}

void process_ip6_response(const struct IcmpPacket *icm, const char *dest_str, double time) {
    printf(
        "%li bytes from %s: icmp_seq=%i time=%.3fms\n", 
        sizeof(*icm), dest_str, icm->h_seq, time
    );
    // We can't parse Ethernet header since we do not use `AF_PACKET`. See `packet(7)`.
    if (config.verbosity > 0) {
        pr_icmp(icm);
        const char *sep = gen_str('=', 55);
        printf("%s\n", sep);
        free((void *)sep);
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

    printf("PING %s (%s): %lu data bytes\n", config.hostname, dest_ip, sizeof(IcmpPacket));

    uint16_t pid = (uint16_t)getpid();
    u_char buf[128] = {0};
    struct iphdr *ip4;
    IcmpPacket *icm = NULL;
    uint16_t max_seq = config.count == 0 ? UINT16_MAX : config.count;
    for (uint16_t seq = 0; seq < max_seq; seq++) {
        if (seq) sleep(1);
        if (config.ip == IPv4) {
            icm = icmp_func.new_echo4_req(pid, seq);
        } else {
            struct sockaddr_in6 *dest = (struct sockaddr_in6 *)&addr;
            // FIXME find out source address
            icm = icmp_func.new_echo6_req(in6addr_loopback, dest->sin6_addr, pid, seq);
        }
        icmp_func.send(icm, sockfd, &addr);
        free(icm);

        glb_state.sent ++;
        IcmpResult res;
        if (config.ip == IPv4) res = icmp_func.recv4(&ip4, &icm, sockfd, buf, sizeof(buf), &from, &from_len);
        else res = icmp_func.recv6(&icm, sockfd, buf, sizeof(buf), &from, &from_len);
        if (res != 0) {
            printf("%s: %s\n", config.bin, icmp_func.strerror(res));
            exit(1);
        }

        glb_state.received ++;
        struct timespec curr_time;
        clock_gettime(CLOCK_MONOTONIC_RAW, &curr_time);
        double time = calc_time(&icm->ts_creation, &curr_time);
        add_time_to_stat(time);

        const char *dest_str = color(dest_ip, UREG, false);
        if (config.ip == IPv4) {
            process_ip4_response(ip4, icm, dest_str, addr.ss_family, time);
        } else {
            process_ip6_response(icm, dest_str, time);
        }
        free((void *)dest_str);
    }
    finish();
    return 0;
}
