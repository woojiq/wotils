#include "include/args.h"

#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct AppConfig config = {
    IPv4, NULL, NULL, 0, ClrAuto, 0
};

void help_message() {
    printf(
        "Usage: %s [OPTION...] hostname\n"
        "Send ICMP ECHO_REQUEST packets to network hosts.\n\n"
        " Options:\n"
        "  -c, --count <NUM>          stop after sending NUMBER packets\n"
        "      --ip4                  use IPv4 for sending packets\n"
        "      --ip6                  use IPv6 for sending packets\n"
        "      --color <WHEN>         WHEN is 'always', 'never', or 'auto'\n"
        "      --help                 show this message\n"
        "  -v, --verbose              verbose output\n"
        , config.bin
    );
}

void usage_and_exit(const int status_code) {
    (void)fprintf(stderr, "Try '%s --help' for more information.\n", config.bin);
    exit(status_code);
}

/// Try to convert Ascii string to unsigned 16-bit integer.
/// Returns `-1` on error or overflow.
int atou16(const char *str, uint16_t *res) {
    uint count = 0;
    for (int i=0; str[i] != '\0'; i++) {
        if (str[i] < '0' || str[i] > '9') return -1;
        // https://stackoverflow.com/a/20956705/17903686
        if (__builtin_umul_overflow(count, 10, &count)) return -1;
        if (__builtin_uadd_overflow(count, str[i] - '0', &count)) return -1;
    }
    if (count > UINT16_MAX) return -1;
    *res = (uint16_t)count;
    return 0;
}

static const struct option long_options[] = {
    {"help", no_argument, 0, 0},
    {"verbose", no_argument, 0, 'v'},
    {"color", required_argument, 0, 0},
    {"count", required_argument, 0, 'c'},
    {"ip4", no_argument, 0, 0},
    {"ip6", no_argument, 0, 0},
    {0, 0, 0, 0}
};

void parse_args_long(int index) {
    switch (index) {
    case 0:
        help_message();
        exit(0);
        break;
    case 2:
        // `strcmp` returns 0 if strings are equal.
        if (!strcmp(optarg, "auto")) config.color = ClrAuto;
        else if (!strcmp(optarg, "always")) config.color = ClrAlways;
        else if (!strcmp(optarg, "never")) config.color = ClrNever;
        else {
            (void)fprintf(
                stderr, "'%s': valid values: auto, always, never.\n", 
                long_options[index].name
            );
            usage_and_exit(1);
        }
        break;
    case 4:
        config.ip = IPv4;
        break;
    case 5:
        config.ip = IPv6;
        break;
    default:
        usage_and_exit(1);
    }
}

void parse_args_short(int opt) {
    switch (opt) {
    case 'v':
        config.verbosity ++;
        break;
    case 'c':
        if (atou16(optarg, &config.count) == -1) {
            (void)fprintf(stderr, "%s: valid count range is [0; %u]\n", config.bin, UINT16_MAX);
            usage_and_exit(1);
        }
        break;
    default:
        usage_and_exit(1);
    }
}

void parse_args(int argc, char *argv[]) {
    config.bin = argv[0];
    int opt = -1, long_index = 0;
    while ((opt = getopt_long(argc, argv, "vc:", long_options, &long_index)) != -1) {
        if (opt == 0) parse_args_long(long_index);
        else parse_args_short(opt);
    }
    if (optind < argc) {
        config.hostname = argv[optind];
    } else {
        usage_and_exit(1);
    }
}
