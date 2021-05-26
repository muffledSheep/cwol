#include <bits/types/time_t.h>
#include <stddef.h>

#include "cache.h"

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <asm-generic/socket.h>
#include <assert.h>
#include <bits/stdint-uintn.h>
#include <bits/types/FILE.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <time.h>
#include <argp.h>
#include <pthread.h>

#include "common.h"

#define PTHREAD_CHECK(code)     \
    if ((code) != 0) {          \
        DIE("Pthread error\n"); \
    }                           \

#define PING_CMD       "ping -c 1 -W 1 %" XSTR(ADDR_STR_MAX_LEN) "s > /dev/null"
#define ARP_CACHE_PATH "/proc/net/arp"
#define ARP_LINE_FMT   "%" XSTR(ADDR_STR_MAX_LEN) "s%*s%*s%" XSTR(MAC_STR_LEN) \
                       "s%*s%*s"
#define ZEROED_MAC     "00:00:00:00:00:00"

enum {
    MAGIC_BYTE   = 0xFF,
    MAGIC_LEN    = 6,
    MAC_REPS     = 16,
    PAYLOAD_LEN = MAGIC_LEN + MAC_REPS * MAC_OCTET_COUNT,
    WOL_PORT     = 7
};

static bool online(const char* addr);
static void send_payload(char MAC[MAC_STR_LEN]);
static void mk_payload(char MAC_str[MAC_BUFF_LEN],
                       uint8_t payload[PAYLOAD_LEN]);
static bool lookup_MAC(const char* addr, char MAC[MAC_BUFF_LEN]);
static bool arp_cache_lookup_MAC(const char* addr, char MAC[MAC_BUFF_LEN]);
static bool wake(const ClientEntry* client);
static bool await_response(const char* addr);
static error_t parse_opt(int key, char* arg, struct argp_state* state);
static void parse_clients(const char** args, size_t args_len,
                          struct argp_state* state);
static void add_clients(size_t len, ClientEntry cls[len]);
static void cleanup(void);
static void wake_clients(void);
static void* wake_worker(void* _);
static void wake_last_woken(void);
static void set_last_woken(void);
static void update_cache(void);

const char* argp_program_version = "wol 1.0";
const char* error_print_prog_name = "wol";

static char doc[] = "QWFX todo."; // QWFX todo
static char args_doc[] = "[ADDRESS [MAC]]";
static struct argp_option opts[] = {
    {"clear-cache", 'c', 0,         0, "Clear cache",                        0},
    {"previous",    'p', 0,         0, "Wake most recently woken client",    0},
    {"wait",        'w', "SECONDS", 0, "Seconds to wait for a client response",
                                                                             0},
    {"interval",    'i', "SECONDS", 0, "Seconds between client response polls",
                                                                             0},
    {"threads",     't', "THREADS", 0, "Number of threads to utilise",       0},
    {"quiet",       'q', 0,         0, "Do not print to standard out",       0},
    {0}
};

static unsigned rsp_timout_secs = 80;
static unsigned rsp_poll_interval_secs = 1;
static unsigned num_threads = -1;
static bool wake_prev = false;
static bool clear_cache = false;
static ClientEntry* clients = NULL;
static bool* successfully_woken = NULL;
static size_t clients_len = 0;
static size_t clients_idx = 0;
static pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

int main(int argc, char** argv) {
    cache_init();

    num_threads = get_nprocs();

    struct argp argp = {opts, parse_opt, args_doc, doc, 0, 0, 0};
    argp_parse(&argp, argc, argv, 0, 0, NULL);

    if ((successfully_woken =
         calloc(clients_len, sizeof *successfully_woken)) == NULL) {
        DIE("Memory error.\n");
    }

    if (clear_cache) {
        cache_clear();
    }

    wake_clients();

    if (wake_prev) {
        wake_last_woken();
    }

    update_cache();
    set_last_woken();

    cleanup();

    return EXIT_SUCCESS;
}

static void cleanup(void) {
    cache_destroy();

    if (clients) {
        free(clients);
        clients = NULL;
    }

    if (successfully_woken) {
        free(successfully_woken);
        successfully_woken = NULL;
    }
}

static void set_last_woken(void) {
    if (!wake_prev && clients_len) {
        cache_set_last_woken(clients[clients_len - 1].addr);
    }
}

static void wake_clients(void) {
    pthread_t threads[num_threads];

    PTHREAD_CHECK(pthread_mutex_init(&clients_mutex, NULL));

    for (unsigned i = 0; i < num_threads; i++) {
        PTHREAD_CHECK(pthread_create(&threads[i], NULL, wake_worker, NULL));
    }

    for (unsigned i = 0; i < num_threads; i++) {
        PTHREAD_CHECK(pthread_join(threads[i], NULL));
    }

    PTHREAD_CHECK(pthread_mutex_destroy(&clients_mutex));
}

static void wake_last_woken(void) {
    ClientEntry last_woken;

    if (cache_get_last_woken(&last_woken)) {
        wake(&last_woken);
    } else {
        print_info("Nothing previously woken\n");
    }
}

static void* wake_worker(void* _) {
    (void)_;

    while (true) {
        PTHREAD_CHECK(pthread_mutex_lock(&clients_mutex));

        if (clients_idx >= clients_len) {
            PTHREAD_CHECK(pthread_mutex_unlock(&clients_mutex));

            break;
        }

        size_t entry_idx = clients_idx++;
        ClientEntry* entry = &clients[entry_idx];

        PTHREAD_CHECK(pthread_mutex_unlock(&clients_mutex));

        if (wake(entry)) {
            successfully_woken[entry_idx] = true;
        }
    }

    return NULL;
}

static error_t parse_opt(int key, char* arg, struct argp_state* state) {
    switch (key) {
        case 'c': clear_cache = true; break;
        case 'p': wake_prev = true; break;
        case 'w':
            if (sscanf(arg, "%u", &rsp_timout_secs) != 1) {
                argp_usage(state);
            }

            break;
        case 'i':
            if (sscanf(arg, "%u", &rsp_poll_interval_secs) != 1) {
                argp_usage(state);
            }

            break;
        case 't':
            if (sscanf(arg, "%u", &num_threads) != 1) {
                argp_usage(state);
            }

            break;
        case 'q': quiet = true; break;
        case ARGP_KEY_ARGS: {
            const char** args = (const char**)(state->argv + state->next);
            size_t args_len = state->argc - state->next;
            parse_clients(args, args_len, state);

            break;
        }
        default: return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static void update_cache(void) {
    for (size_t i = 0; i < clients_len; i++) {
        if (successfully_woken[i]) {
            cache_update(clients[i].addr, clients[i].MAC);
        }
    }
}

static void parse_clients(const char** args, size_t args_len,
                          struct argp_state* state) {
    ClientEntry* entry = NULL;
    ClientEntry tmp[args_len];
    size_t tmp_len = 0;
    memset(tmp, 0, sizeof tmp);

    for (size_t i = 0; i < args_len; i++) {
        if (valid_addr(args[i])) {
            entry = &tmp[tmp_len++];
            strcpy(entry->addr, args[i]);
        } else if (valid_MAC(args[i])) {
            if (!entry || strlen(entry->addr) == 0) {
                argp_error(state, "MAC must follow address: %s", args[i]);
            }

            strcpy(entry->MAC, args[i]);
        } else {
            argp_error(state, "Invalid address or MAC: %s", args[i]);
        }
    }

    add_clients(tmp_len, tmp);
}

static void add_clients(size_t len, ClientEntry cls[len]) {
    if ((clients = calloc(len, sizeof *cls)) == NULL) {
        DIE("Memory error\n");
    }

    for (size_t i = 0; i < len; i++) {
        if (strlen(cls[i].MAC) == 0) {
            ClientEntry cached;
            char MAC[MAC_BUFF_LEN];

            if (cache_get(cls[i].addr, &cached)) {
                strcpy(clients[i].MAC, cached.MAC);
            } else if (lookup_MAC(cls[i].addr, MAC)) {
                strcpy(clients[i].MAC, MAC);
            } else {
                print_info("Could not resolve MAC for: %s\n", cls[i].addr);
                continue;
            }
        }

        memcpy(&clients[clients_len++], &cls[i], sizeof *cls);
    }
}

static bool wake(const ClientEntry* client) {
    time_t tick;
    time(&tick);

    send_payload((char*)client->MAC);
    bool got_rsp = await_response(client->addr);

    time_t tock;
    time(&tock);

    const char* msg = got_rsp ? "%s success after %g second(s)\n"
                              : "%s failure after %g second(s)\n";
    print_info(msg, client->addr, difftime(tock, tick));

    return got_rsp;
}

static bool await_response(const char* addr) {
    time_t start;
    time(&start);

    while (true) {
        if (online(addr)) {
            return true;
        }

        time_t tick;
        time(&tick);

        if (difftime(tick, start) >= rsp_timout_secs) {
            break;
        }

        time_t tock;
        time(&tock);

        long delay = rsp_poll_interval_secs - difftime(tock, tick);
        sleep((delay < 0) ? 0 : delay);
    }

    return online(addr);
}

static bool lookup_MAC(const char* addr, char MAC[MAC_BUFF_LEN]) {
    size_t cmd_len = snprintf(NULL, 0, PING_CMD, addr) + 1;
    char ping_cmd[cmd_len + 1];
    snprintf(ping_cmd, cmd_len, PING_CMD, addr);

    system(ping_cmd); // Try populate ARP cache

    return arp_cache_lookup_MAC(addr, MAC);
}

static bool arp_cache_lookup_MAC(const char* addr, char MAC[MAC_BUFF_LEN]) {
    FILE* arp_fp = fopen(ARP_CACHE_PATH, "r");

    if (arp_fp == NULL || ferror(arp_fp)) {
        DIE("Could not open arp cache for reading\n");
    }

    fscanf(arp_fp, "%*[^\n]\n"); // Skip header

    char ln_addr[ADDR_BUFF_LEN];
    char ln_MAC[MAC_BUFF_LEN];
    bool found_addr = false;

    while (fscanf(arp_fp, ARP_LINE_FMT, ln_addr, ln_MAC) != EOF) {
        if (strcmp(ln_addr, addr) == 0 && strcmp(ln_MAC, ZEROED_MAC) != 0) {
            strncpy(MAC, ln_MAC, sizeof ln_MAC);
            found_addr = true;

            break;
        }
    }

    fclose(arp_fp);

    return found_addr;
}

static void mk_payload(char MAC_str[MAC_BUFF_LEN],
                       uint8_t payload[PAYLOAD_LEN]) {
    uint8_t MAC[MAC_OCTET_COUNT];
    assert(parse_MAC(MAC_str, MAC));

    int k = 0;

    while (k < MAGIC_LEN) {
        payload[k++] = MAGIC_BYTE;
    }

    for (int i = 0; i < MAC_OCTET_COUNT * MAC_REPS; i++, k++) {
        payload[k] = MAC[i % MAC_OCTET_COUNT];
    }

    assert(k == PAYLOAD_LEN);
}

static void send_payload(char MAC[MAC_STR_LEN]) {
    uint8_t payload[PAYLOAD_LEN];
    mk_payload(MAC, payload);

    int sock;

    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        DIE("Network error\n");
    }

    int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &yes, sizeof yes);
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(WOL_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);

    if (sendto(sock, payload, sizeof payload, 0, (struct sockaddr*)&addr,
               sizeof(struct sockaddr_in)) < 0) {
        DIE("Network error\n");
    }

    close(sock);
}

static bool online(const char* addr) {
    int sock;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        DIE("Network error\n");
    }

    int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    struct sockaddr_in sock_addr;
    memset(&sock_addr, 0, sizeof sock_addr);

    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = inet_addr(addr);

    enum { PING_PORT = 22 };
    sock_addr.sin_port = htons(PING_PORT);

    if (connect(sock, (struct sockaddr*)&sock_addr, sizeof sock_addr)) {
        return false;
    }

    close(sock);

    return true;
}

