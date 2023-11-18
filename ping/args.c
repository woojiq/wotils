#include "include/args.h"

#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct AppConfig Config = {
    IPv4, NULL, NULL, 0, ClrAuto, 0
};

void help_message() {
    printf(
        "Usage: %s [OPTION...] hostname\n"
        "Send ICMP ECHO_REQUEST packets to network hosts.\n\n"
        " Options:\n"
        "  -c, --count <NUM>          stop after sending NUMBER packets\n"
        "      --ip <4|6|auto>        ip version to use\n"
        "      --color <WHEN>         WHEN is 'always', 'never', or 'auto'\n"
        "      --help                 show this message\n"
        "  -v, --verbose              verbose output\n"
        , Config.bin
    );
}

void usage_and_exit(const int status_code) {
    fprintf(stderr, "Try '%s --help' for more information.\n", Config.bin);
    exit(status_code);
}

/// Try to convert Ascii string to unsigned 16-bit integer.
/// Returns `-1` on error or overflow.
int atou16(const char *str, uint16_t *res) {
    uint count = 0;
    bool ok;
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

void parse_args(int argc, char *argv[]) {
    static const struct option long_options[] = {
        {"help", no_argument, 0, 0},
        {"verbose", no_argument, 0, 'v'},
        {"color", required_argument, 0, 0},
        {"count", required_argument, 0, 'c'},
        {"ip", required_argument, 0, 0},
        {0, 0, 0, 0}
    };

    Config.bin = argv[0];
    int opt = -1, long_index = 0;
    while ((opt = getopt_long(argc, argv, "vc:", long_options, &long_index)) != -1) {
        if (opt == 0) {
            switch (long_index) {
            case 0:
                help_message();
                exit(0);
                break;
            case 2:
                // `strcmp` returns 0 if strings are equal.
                if (!strcmp(optarg, "auto")) Config.color = ClrAuto;
                else if (!strcmp(optarg, "always")) Config.color = ClrAlways;
                else if (!strcmp(optarg, "never")) Config.color = ClrNever;
                else {
                    fprintf(
                        stderr, "'%s': valid values: auto, always, never.\n", 
                        long_options[long_index].name
                    );
                    usage_and_exit(1);
                }
                break;
            case 4:
                if (!strcmp(optarg, "4")) Config.ip = IPv4;
                else if (!strcmp(optarg, "6")) Config.ip = IPv6;
                else if (!strcmp(optarg, "auto")) Config.ip = IPAny;
                else {
                    fprintf(
                        stderr, "'%s': valid values: 4, 6, auto.\n", 
                        long_options[long_index].name
                    );
                    usage_and_exit(1);
                }
                break;
            default:
                usage_and_exit(1);
            }
        } else {
            switch (opt) {
            case 'v':
                Config.verbosity ++;
                break;
            case 'c':
                if (atou16(optarg, &Config.count) == -1) {
                    fprintf(stderr, "%s: valid count range is [0; %u]\n", Config.bin, UINT16_MAX);
                    usage_and_exit(1);
                }
                break;
            default:
                usage_and_exit(1);
            }
        }
    }
    if (optind < argc) {
        Config.hostname = argv[optind];
    } else {
        usage_and_exit(1);
    }
}
