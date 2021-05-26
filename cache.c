#define _POSIX_C_SOURCE 199309L

#include <bits/types/FILE.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>

#include "cache.h"
#include "common.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/file.h>
#include <dirent.h>
#include <stdio.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <linux/limits.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#define DATA_DIR        ".cwol"
#define CACHE_FILE      "cache"
#define LAST_WOKEN_FILE "last_woken"

#define LAST_WOKEN_LINE_READ_FMT  "%" XSTR(ADDR_STR_MAX_LEN) "s"
#define LAST_WOKEN_LINE_WRITE_FMT "%s\n"
#define CACHE_LINE_WRITE_FMT      "%s %s\n"
#define CACHE_LINE_READ_FMT       "%" XSTR(ADDR_STR_MAX_LEN) "s %"  \
                                  XSTR(MAC_STR_LEN) "s"

enum {
    // Includes space and \0
    CACHE_LINE_BUFF_SIZE = ADDR_STR_MAX_LEN + MAC_STR_LEN + 2
};

static void init_data_dir(void);
static void dat_dir_name(size_t n, char buff[n], const char* name);
static void create_if_necessary(const char* name);
static void lock(struct flock* fl, FILE* fp);
static void unlock(struct flock* fl, FILE* fp);
static int next_line(FILE* fp, ClientEntry* result);
static int line_num(FILE* fp, const char* addr);
static FILE* tmp_copy(FILE* fp);

static FILE* cache_fp = NULL;
static struct flock cache_fl;
static struct flock last_woken_fl;
static char cache_fname[PATH_MAX + 1];
static char last_woken_fname[PATH_MAX + 1];

int cache_init(void) {
    init_data_dir();

    if ((cache_fp = fopen(cache_fname, "a+")) == NULL) {
        DIE("Failed to open file: '%s'", cache_fname);
    }

    memset(&cache_fl, 0, sizeof cache_fl);
    memset(&last_woken_fl, 0, sizeof last_woken_fl);

    return 0;    
}

void cache_destroy(void) {
    fclose(cache_fp);
}

int cache_add(const char* addr, const char* MAC) {
    assert(valid_addr(addr) && valid_MAC(MAC));

    lock(&cache_fl, cache_fp);

    int res = 0;

    if (cache_contains(addr)) {
        res = -1;
    } else {
        fseek(cache_fp, 0, SEEK_END);

        if (fprintf(cache_fp, CACHE_LINE_WRITE_FMT, addr, MAC) < 0) {
            DIE("Failed to write to: '%s'\n", cache_fname);
        }

        fflush(cache_fp);
    }

    unlock(&cache_fl, cache_fp);

    return res;
}

int cache_remove(const char* addr) {
    assert(valid_addr(addr));

    lock(&cache_fl, cache_fp); 

    int res = 0;
    int ignored_ln = line_num(cache_fp, addr);

    if (ignored_ln == -1) {
        res = -1;
    } else {
        FILE* tmp_fp = tmp_copy(cache_fp);

        if (tmp_fp == NULL) {
            DIE("Failed to write temp file\n");
        }

        cache_clear();

        rewind(tmp_fp);

        ClientEntry entry;
        int status;

        for (int line = 0; (status = next_line(tmp_fp, &entry)); line++) {
            if (status == -1) {
                DIE("Failed to parse temp file\n");
            }

            if (line == ignored_ln) {
                continue;
            }

            if (fprintf(cache_fp, CACHE_LINE_WRITE_FMT, entry.addr,
                        entry.MAC) < 0) {
                DIE("Could not write to: '%s'\n", cache_fname);
            }
        }

        fclose(cache_fp);
        fclose(tmp_fp);
        cache_init();
    }

    unlock(&cache_fl, cache_fp);

    return res;
}

void cache_update(const char* addr, const char* MAC) {
    lock(&cache_fl, cache_fp);

    cache_remove(addr);
    cache_add(addr, MAC);

    unlock(&cache_fl, cache_fp);
}

void cache_clear(void) {
    lock(&cache_fl, cache_fp);

    fclose(cache_fp);
    cache_fp = fopen(cache_fname, "w"); // Truncate

    if (cache_fp == NULL) {
        DIE("Failed to open: '%s'\n", cache_fname);
    }

    unlock(&cache_fl, cache_fp);
}

bool cache_contains(const char* addr) {
    lock(&cache_fl, cache_fp);

    int line = line_num(cache_fp, addr);

    unlock(&cache_fl, cache_fp);

    return line != -1;
}

bool cache_get_last_woken(ClientEntry* result) {
    FILE* fp = fopen(last_woken_fname, "a+");

    if (fp == NULL || ferror(fp)) {
        DIE("Failed to open: '%s'\n", last_woken_fname);
    }

    lock(&last_woken_fl, fp);

    char addr[ADDR_BUFF_LEN];
    bool success = false;

    rewind(fp);

    if (fscanf(fp, LAST_WOKEN_LINE_READ_FMT, addr) == 1) {
        if (!valid_addr(addr)) {
            DIE("Failed to parse: '%s'\n", last_woken_fname);
        }

        success = cache_get(addr, result);
    }

    unlock(&last_woken_fl, fp);
    fclose(fp);

    return success;
}

bool cache_get(const char* addr, ClientEntry* result) {
    lock(&cache_fl, cache_fp);

    rewind(cache_fp);

    bool found_addr = false;
    ClientEntry entry;
    int status;

    for (int line = 1; !found_addr &&
         (status = next_line(cache_fp, &entry)); line++) {
        if (status == -1) {
            DIE("Error parsing '%s' at line: %d\n", cache_fname, line);
        }

        if (strncmp(entry.addr, addr, strlen(addr)) == 0) {
            strncpy((char*)&result->addr, entry.addr, strlen(entry.addr) + 1);
            strncpy((char*)&result->MAC, entry.MAC, strlen(entry.MAC) + 1);
            found_addr = true;
        }
    }

    unlock(&cache_fl, cache_fp);

    return found_addr;
}

void cache_set_last_woken(const char* addr) {
    FILE* fp = fopen(last_woken_fname, "w");

    if (fp == NULL || ferror(fp)) {
        DIE("Failed to open: '%s'\n", last_woken_fname);
    }

    lock(&last_woken_fl, fp);

    if (fprintf(fp, LAST_WOKEN_LINE_WRITE_FMT, addr) < 0) {
        DIE("Failed to write to: '%s'\n", last_woken_fname);
    }

    fflush(fp);

    unlock(&last_woken_fl, fp);
    fclose(fp);
}

static FILE* tmp_copy(FILE* fp) {
    FILE* tmp_fp = tmpfile();

    if (tmp_fp == NULL) {
        return NULL;
    }

    rewind(fp);

    int status;
    ClientEntry entry;

    while ((status = next_line(fp, &entry))) {
        bool rw_err = status == -1 || fprintf(tmp_fp, CACHE_LINE_WRITE_FMT,
            entry.addr, entry.MAC) < 0;

        if (rw_err) {
            fclose(tmp_fp);

            return NULL;
        }
    }

    return tmp_fp;
}

static int line_num(FILE* fp, const char* addr) {
    rewind(fp);

    int status;
    ClientEntry entry;

    for (int line = 0; (status = next_line(cache_fp, &entry)); line++) {
        if (status == -1) {
            DIE("Error parsing '%s' at line: %d\n", cache_fname, line);
        }

        if (strncmp(entry.addr, addr, strlen(addr)) == 0) {
            return line;
        }
    }

    return -1;
}

static void init_data_dir(void) {
    char dir_name[PATH_MAX + 1];
    dat_dir_name(sizeof dir_name, dir_name, "");

    DIR* dir = opendir(dir_name);

    if (dir) {
        closedir(dir);
    } else {
        if (mkdir(dir_name, S_IRWXU) == -1) {
            DIE("Failed to create data directory in: '%s'\n", dir_name);
        }
    }

    dat_dir_name(sizeof cache_fname, cache_fname, CACHE_FILE);
    dat_dir_name(sizeof last_woken_fname, last_woken_fname, LAST_WOKEN_FILE);
    
    create_if_necessary(cache_fname);
    create_if_necessary(last_woken_fname);
}

// -1 - error; 0 - eof; 1 - OK
static int next_line(FILE* fp, ClientEntry* entry) {
    char ln_buff[CACHE_LINE_BUFF_SIZE];
    fgets(ln_buff, sizeof ln_buff, fp);

    if (feof(fp)) {
        return 0;
    }

    if (ferror(fp)) {
        DIE("IO error\n");
    }

    if (sscanf(ln_buff, CACHE_LINE_READ_FMT, (char*)&entry->addr,
               (char*)&entry->MAC) != 2) {
        return -1;
    }

    return valid_addr(entry->addr) && valid_MAC(entry->MAC) ? 1 : -1;
}


static void lock(struct flock* fl, FILE* fp) {
    fl->l_type = F_WRLCK;
    fl->l_whence = SEEK_SET;
    fl->l_start = 0;
    fl->l_len = 0;
    int fd = fileno(fp); // QWFX may need to move away from std descs

    enum {
        LOCK_ATTEMPT_LIMIT       = 5,
        LOCK_ATTEMPT_INTERVAL_MS = 500
    };

    for (int attempt = 0; attempt < LOCK_ATTEMPT_LIMIT; attempt++) {
        if (fcntl(fd, F_SETLK, fl) != -1) {
            return;
        }

        struct timespec delay = {.tv_sec = 0,
                                 .tv_nsec = LOCK_ATTEMPT_INTERVAL_MS * 1000};
        nanosleep(&delay, NULL);
    }

    DIE("Failed to acquire file lock\n");
}

static void unlock(struct flock* fl, FILE* fp) {
    fl->l_type = F_UNLCK;
    int fd = fileno(fp);

    if (fcntl(fd, F_SETLK, fl) == -1) {
        DIE("Failed to unlock file");
    }
}

static void create_if_necessary(const char* name) {
    FILE* fp = fopen(name, "a");

    if (fp) {
        fclose(fp);
    } else {
        DIE("failed to create file: '%s'", name);
    }
}

static void dat_dir_name(size_t n, char buff[n], const char* name) {
    const char* home = getenv("HOME");
    const char* fmt = "%s/%s/%s";
    size_t size = snprintf(NULL, 0, fmt, home, DATA_DIR, name) + 1;

    assert(size <= n);

    snprintf(buff, n, fmt, home, DATA_DIR, name);
}
