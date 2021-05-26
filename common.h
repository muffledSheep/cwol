#pragma once

#include <bits/stdint-uintn.h>
#include <linux/if_ether.h>
#include <stdbool.h>

#define DIE(...) do {                 \
    if (!quiet) {                     \
        fprintf(stderr, __VA_ARGS__); \
    }                                 \
                                      \
    exit(1);                          \
} while (0);

#define MAC_STR_LEN      17 /* e.g. DE:AD:BE:EF:00:00 (2 * ETH_ALEN + 5) */
#define MAC_BUFF_LEN     (MAC_STR_LEN + 1)
#define MAC_OCTET_COUNT  ETH_ALEN
#define ADDR_STR_MAX_LEN 15 /* IPv4 */
#define ADDR_BUFF_LEN    (ADDR_STR_MAX_LEN + 1)

#define STR(s) #s
#define XSTR(s) STR(s)

extern bool quiet;

int print_info(const char* __restrict fmt, ...);

bool parse_MAC(const char* src, uint8_t dest[MAC_OCTET_COUNT]);

bool valid_addr(const char* addr);

bool valid_MAC(const char* MAC);
