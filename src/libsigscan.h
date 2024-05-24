/**
 * @file   libsigscan.h
 * @brief  Single-header signature scanning library
 * @author 8dcc
 *
 * https://github.com/8dcc/libsigscan
 */

#ifndef LIBSIGSCAN_H_
#define LIBSIGSCAN_H_ 1

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>    /* fopen(), FILE* */
#include <string.h>   /* strstr() */
#include <stdlib.h>   /* strtoull() */
#include <dirent.h>   /* readdir() */
#include <regex.h>    /* regcomp(), regexec(), etc. */
#include <sys/mman.h> /* mmap() */
#include <errno.h>    /* errno */

/*----------------------------------------------------------------------------*/
/* Private macros */

#ifdef LIBSIGSCAN_DEBUG
#define LIBSIGSCAN_ERR(...)              \
    do {                                 \
        fprintf(stderr, "libsigscan: "); \
        fprintf(stderr, __VA_ARGS__);    \
        fputc('\n', stderr);             \
    } while (0)
#else
#define LIBSIGSCAN_ERR(...) \
    do {                    \
    } while (0)
#endif

/*----------------------------------------------------------------------------*/
/* Private structures */

typedef enum LibsigscanEPidTypes {
    LIBSIGSCAN_PID_INVALID = -2, /* Invalid PID, should be ignored */
    LIBSIGSCAN_PID_SELF    = -1, /* We want to search in our own modules */
} LibsigscanEPidTypes;

typedef struct LibsigscanModuleBounds {
    void* start;
    void* end;
    struct LibsigscanModuleBounds* next;
} LibsigscanModuleBounds;

/*----------------------------------------------------------------------------*/
/* Private functions */

/* Returns true if string `str' mathes regex pattern `pat'. Pattern uses BRE
 * syntax: https://www.gnu.org/software/sed/manual/html_node/BRE-syntax.html */
static bool libsigscan_regex(regex_t expr, const char* str) {
    int code = regexec(&expr, str, 0, NULL, 0);
    if (code > REG_NOMATCH) {
        char err[100];
        regerror(code, &expr, err, sizeof(err));
        LIBSIGSCAN_ERR("regexec() returned an error: %s\n", err);
        return false;
    }

    /* REG_NOERROR: Success
     * REG_NOMATCH: Pattern did not match */
    return code == REG_NOERROR;
}

/*
 * Parse /proc/self/maps to get the start and end addresses of the specified
 * module.
 *
 * The function assumes the format of maps is always:
 *   0000DEADBEEF-0000ABADCAFE rwxp 000123AB 100:00 12345678   /path/module
 *
 * Each line is expected to match the following scanf() format:
 *   "%lx-%lx %s %s %s %s %s"
 */
static LibsigscanModuleBounds* libsigscan_get_module_bounds(int pid,
                                                            const char* regex) {
    static regex_t compiled_regex;

    /* Compile regex pattern once here */
    if (regex != NULL && regcomp(&compiled_regex, regex, REG_EXTENDED) != 0) {
        LIBSIGSCAN_ERR("regcomp() returned an error code for pattern \"%s\"\n",
                       regex);
        return NULL;
    }

    /* Get the full path to /proc/PID/maps from the specified PID */
    static char maps_path[50] = "/proc/self/maps";
    if (pid != LIBSIGSCAN_PID_SELF)
        sprintf(maps_path, "/proc/%d/maps", pid);

    /* Open the maps file */
    FILE* fd = fopen(maps_path, "r");
    if (!fd) {
        LIBSIGSCAN_ERR("Couldn't open /proc/%d/maps", pid);
        return NULL;
    }

    /* For the first module. Start `ret' as NULL in case no module is valid. */
    LibsigscanModuleBounds* ret = NULL;
    LibsigscanModuleBounds* cur = ret;

    /* Buffers used in the loop by fgets() and sscanf() */
    static char line_buf[300];
    static char rwxp[5];
    static char offset[17];
    static char dev[10];
    static char inode[10];
    static char pathname[200];

    while (fgets(line_buf, sizeof(line_buf), fd)) {
        /* Scan the current line using sscanf(). We need to change address sizes
         * depending on the arch. */
        long unsigned start_num, end_num;
        sscanf(line_buf, "%lx-%lx %s %s %s %s %s", &start_num, &end_num, rwxp,
               offset, dev, inode, pathname);

        void* start_addr = (void*)start_num;
        void* end_addr   = (void*)end_num;

        /* Parse "rwxp". For now we only care about read permissions. */
        bool is_readable = rwxp[0] == 'r';

        bool name_matches = true;
        if (regex == NULL) {
            /* We don't want to filter the module name, just make sure it
             * doesn't start with '[' and skip to the end of the line. */
            if (pathname[0] == '[')
                name_matches = false;
        } else {
            /* Compare module name against provided regex. Note that the output
             * of maps has absolute paths. */
            if (!libsigscan_regex(compiled_regex, pathname))
                name_matches = false;
        }

        /* We can read it, and it's the module we are looking for. */
        if (is_readable && name_matches) {
            if (cur == NULL) {
                /* Allocate the first bounds struct */
                cur = (LibsigscanModuleBounds*)malloc(
                  sizeof(LibsigscanModuleBounds));

                /* This one will be returned */
                ret = cur;

                /* Save the addresses from this line of maps */
                cur->start = start_addr;
                cur->end   = end_addr;
            } else if (cur->end == start_addr && cur->end < end_addr) {
                /* If the end address of the last struct is the start of this
                 * one, just merge them. */
                cur->end = end_addr;
            } else {
                /* There was a gap between the end of the last block and the
                 * start of this one, allocate new struct. */
                cur->next = (LibsigscanModuleBounds*)malloc(
                  sizeof(LibsigscanModuleBounds));

                /* Set as current */
                cur = cur->next;

                /* Save the addresses from this line of maps */
                cur->start = start_addr;
                cur->end   = end_addr;
            }

            /* Indicate the end of the linked list */
            cur->next = NULL;
        }
    }

    /* If we compiled a regex expression, free it before returning */
    if (regex != NULL)
        regfree(&compiled_regex);

    fclose(fd);
    return ret;
}

/* Free a linked list of ModuleBounds structures */
static void libsigscan_free_module_bounds(LibsigscanModuleBounds* bounds) {
    LibsigscanModuleBounds* cur = bounds;
    while (cur != NULL) {
        LibsigscanModuleBounds* next = cur->next;
        free(cur);
        cur = next;
    }
}

/* Used for getting the bytes from IDA patterns.
 * Converts: "E0" -> 224 */
static uint8_t libsigscan_hex2byte(const char* hex) {
    int ret = 0;

    /* Skip leading spaces, if any */
    while (*hex == ' ')
        hex++;

    /* Store a byte (two digits of string) */
    for (int i = 0; i < 2 && hex[i] != '\0'; i++) {
        char c = hex[i];

        /* For example "E ", although the format should always be "0E" */
        if (c == ' ')
            break;

        uint8_t n = 0;
        if (c >= '0' && c <= '9')
            n = c - '0';
        else if (c >= 'a' && c <= 'f')
            n = 10 + c - 'a';
        else if (c >= 'A' && c <= 'F')
            n = 10 + c - 'A';

        /* Shift size of 0xF and add the next half of byte */
        ret <<= 4;
        ret |= n & 0xF;
    }

    return ret & 0xFF;
}

/*
 * Convert `ida' signature to code + mask format. Allocate `code_ptr' and
 * `mask_ptr'.
 *
 * IDA format:  "FF ? ? 89"
 * Code format: "\xFF\x00\x00\x89"
 * Mask format: "x??x"
 */
static void libsigscan_ida2code(const char* ida, uint8_t** code_ptr,
                                char** mask_ptr) {
    int arr_sz    = 100;
    uint8_t* code = *code_ptr = (uint8_t*)malloc(arr_sz);
    char* mask = *mask_ptr = (char*)malloc(arr_sz);

    /* Skip preceding spaces from pattern, if any */
    while (*ida == ' ')
        ida++;

    int i;
    for (i = 0; *ida != '\0'; i++) {
        /* If the output arrays are full, reallocate. The `arr_sz' variable is
         * used for both `code' and `mask' arrays. */
        if (i >= arr_sz) {
            arr_sz += 100;
            code = *code_ptr = (uint8_t*)realloc(code, arr_sz);
            mask = *mask_ptr = (char*)realloc(mask, arr_sz);
        }

        if (*ida == '?') {
            code[i] = 0x00;
            mask[i] = '?';

            /* "A1 ?? ?? B2" -> "A1 ? ? B2" */
            while (*ida == '?')
                ida++;
        } else {
            /* Convert "E0" into 224 */
            code[i] = libsigscan_hex2byte(ida);
            mask[i] = 'x';

            /* Go to next byte separator in pattern (space) */
            while (*ida != ' ' && *ida != '\0')
                ida++;
        }

        /* Skip trailing spaces */
        while (*ida == ' ')
            ida++;
    }

    if (i >= arr_sz)
        mask = *mask_ptr = (char*)realloc(mask, arr_sz + 1);

    /* Indicate the end of the pattern in the mask, since 0x00 is valid in
     * code[] */
    mask[i] = '\0';
}

/* Search for pattern `ida' from `start' to `end' inside the memory of `pid' */
static void* libsigscan_pid_scan(int pid, uintptr_t start, uintptr_t end,
                                 const char* ida) {
    if (!start || !end) {
        LIBSIGSCAN_ERR("do_scan() got invalid start or end pointers");
        return NULL;
    }

    uint8_t* pattern;
    char* mask;
    libsigscan_ida2code(ida, &pattern, &mask);

    static char mem_path[50] = "/proc/self/mem";
    if (pid != LIBSIGSCAN_PID_SELF)
        sprintf(mem_path, "/proc/%d/mem", pid);

    FILE* fp = fopen(mem_path, "r");
    if (fp == NULL) {
        LIBSIGSCAN_ERR("Couldn't open %s", mem_path);
        return NULL;
    }

    size_t region_size = end - start;

    /* Map the first N bytes of `fp' at offset 0 to the returned pointer */
    void* mapped_start =
      mmap(NULL, region_size, PROT_READ, MAP_SHARED, fileno(fp), start);

    /* FIXME: This always fails with errno: ENODEV (19) No such device */
    if (mapped_start == MAP_FAILED) {
        LIBSIGSCAN_ERR("mmap() returned MAP_FAILED. Errno: %d\n", errno);
        return NULL;
    }

    /* Current position in memory */
    uint8_t* start_ptr = (uint8_t*)mapped_start;
    uint8_t* mem_ptr   = start_ptr;

    int pat_pos  = 0;
    int mask_pos = 0;

    /* Iterate until we reach the end of the memory or the end of the pattern */
    while ((uintptr_t)mem_ptr < end && mask[mask_pos] != '\0') {
        if (mask[mask_pos] == '?' || *mem_ptr == pattern[pat_pos]) {
            /* Either there was a wildcard on the mask, or we found exact byte
             * match with the pattern. Go to next byte in memory. */
            mem_ptr++;
            pat_pos++;
            mask_pos++;
        } else {
            /* Byte didn't match, check pattern from the begining on the next
             * position in memory */
            start_ptr++;
            mem_ptr  = start_ptr;
            pat_pos  = 0;
            mask_pos = 0;
        }
    }

    /* If we reached end of the mask (i.e. pattern), return the match.
     * Otherwise, NULL. */
    void* ret = (mask[mask_pos] == '\0') ? start_ptr : NULL;

    fclose(fp);
    free(pattern);
    free(mask);

    return ret;
}

/*----------------------------------------------------------------------------*/
/* Public functions */

/* Get the PID of the first process that matches `process_name' */
int sigscan_pidof(const char* process_name) {
    static char filename[50];
    static char cmdline[256];

    DIR* dir = opendir("/proc");
    if (dir == NULL)
        return LIBSIGSCAN_PID_INVALID;

    struct dirent* de;
    while ((de = readdir(dir)) != NULL) {
        /* The name of each folder inside /proc/ is a PID */
        int pid = atoi(de->d_name);
        if (pid <= 0)
            continue;

        /* See proc_cmdline(5). You can also try:
         *   cat /proc/self/maps | xxd   */
        sprintf(filename, "/proc/%d/cmdline", pid);

        FILE* fd = fopen(filename, "r");
        if (fd == NULL)
            continue;

        char* fgets_ret = fgets(cmdline, sizeof(cmdline), fd);
        fclose(fd);

        if (fgets_ret == NULL)
            continue;

        /* We found the PID */
        if (strstr(cmdline, process_name)) {
            closedir(dir);
            return pid;
        }
    }

    /* We checked all /proc/.../cmdline's and we didn't find the process */
    closedir(dir);
    return LIBSIGSCAN_PID_INVALID;
}

/*
 * Search for `ida_pattern' in all the loaded modules of `pid', also matching
 * `regex'.
 *
 * If `pid' is negative, it searches in the currently loaded modules.
 * If `regex' is NULL, it doesn't filter regex.
 */
static void* sigscan_pid_module(int pid, const char* regex,
                                const char* ida_pattern) {
    if (pid == LIBSIGSCAN_PID_INVALID)
        return NULL;

    /* Get a linked list of ModuleBounds, containing the start and end addresses
     * of all the regions whose name matches `regex'. */
    LibsigscanModuleBounds* bounds = libsigscan_get_module_bounds(pid, regex);

    /* Iterate them, and scan each one until we find a match. */
    void* ret = NULL;
    for (LibsigscanModuleBounds* cur = bounds; cur != NULL; cur = cur->next) {
        void* cur_result =
          libsigscan_pid_scan(pid, (uintptr_t)cur->start, (uintptr_t)cur->end,
                              ida_pattern);

        if (cur_result != NULL) {
            ret = cur_result;
            break;
        }
    }

    /* Free the ModuleBounds linked list */
    libsigscan_free_module_bounds(bounds);

    return ret;
}

/* Search for `ida_pattern' in all the loaded modules of `pid'. */
static inline void* sigscan_pid(int pid, const char* ida_pattern) {
    return sigscan_pid_module(pid, NULL, ida_pattern);
}

/* Search for `ida_pattern' in all the loaded modules matching `regex'. */
static inline void* sigscan_module(const char* regex, const char* ida_pattern) {
    return sigscan_pid_module(LIBSIGSCAN_PID_SELF, regex, ida_pattern);
}

/* Search for `ida_pattern' in all the loaded modules. */
static inline void* sigscan(const char* ida_pattern) {
    return sigscan_pid_module(LIBSIGSCAN_PID_SELF, NULL, ida_pattern);
}

#endif /* LIBSIGSCAN_H_ */
