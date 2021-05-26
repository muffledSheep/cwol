#pragma once

#include <stddef.h>
#include <stdbool.h>

#include "common.h"

typedef struct ClientEntry ClientEntry;

struct ClientEntry {
    char addr[ADDR_STR_MAX_LEN + 1];
    char MAC[MAC_STR_LEN + 1];
};

int cache_init(void);

void cache_destroy(void);

int cache_add(const char* addr, const char* MAC);

bool cache_get(const char* addr, ClientEntry* result);

int cache_remove(const char* addr);

void cache_update(const char* addr, const char* MAC);

void cache_clear(void);

bool cache_contains(const char* addr);

bool cache_get_last_woken(ClientEntry* result);

void cache_set_last_woken(const char* addr);
