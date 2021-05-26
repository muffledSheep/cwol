#include "common.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdarg.h>

#define MAC_STR_FMT "%02x:%02x:%02x:%02x:%02x:%02x%*c"

bool quiet = false;

int print_info(const char* __restrict fmt, ...) {
    if (quiet) {
        return 0;
    }

    va_list ap;

    va_start(ap, fmt);

    int ret = vprintf(fmt, ap);

    va_end(ap);

    return ret;
}

bool parse_MAC(const char* src, uint8_t dest[MAC_OCTET_COUNT]) {
    if (!valid_MAC(src)) {  
        return false;
    }

    unsigned digits[MAC_OCTET_COUNT];

    if (sscanf(src, MAC_STR_FMT, &digits[0], &digits[1], &digits[2], &digits[3],
               &digits[4], &digits[5]) == MAC_OCTET_COUNT) {
        for (int i = 0; i < MAC_OCTET_COUNT; i++) {
            dest[i] = (uint8_t)digits[i];
        }

        return true;
    }

    return false;
}

bool valid_MAC(const char* MAC) {
    if (strlen(MAC) != MAC_STR_LEN) {
        return false;
    }

    unsigned x;

    return sscanf(MAC, MAC_STR_FMT, &x, &x, &x, &x, &x, &x) == MAC_OCTET_COUNT;
}

bool valid_addr(const char* addr) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, addr, &sa.sin_addr) != 0;
}
