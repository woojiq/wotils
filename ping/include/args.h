#ifndef PING_ARGS_H_
#define PING_ARGS_H_

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/// Print help message to the stdin.
void help_message();

/// Print usage message to the stdin and exit with status code.
void usage_and_exit(int status_code);

enum ip_config {
    IPv4 = 4,
    IPv6 = 6,
    IPAny = 0,
};

enum color_config {
    ClrAlways = 1,
    ClrNever = -1,
    ClrAuto = 0
};

struct AppConfig {
    enum ip_config ip;
    char *hostname;
    char *bin;
    uint verbosity;
    enum color_config color;
    /// How many packets to send (0 - infinity).
    // uint16 because icmp.seq field is uint16.
    uint16_t count;
} extern Config;

/// Parse command line arguments into `config` global variable.
void parse_args(int argc, char *argv[]);

#endif
