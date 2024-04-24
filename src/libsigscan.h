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
#include <stdio.h>  /* fopen(), FILE* */
#include <stdlib.h> /* strtoull() */
#include <regex.h>  /* regcomp(), regexec(), etc. */

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
 *   "%lx-%lx %s %s %s %s %200[^\n]"
 */
static LibsigscanModuleBounds* libsigscan_get_module_bounds(const char* regex) {
    static regex_t compiled_regex;

    /* Compile regex pattern once here */
    if (regex != NULL && regcomp(&compiled_regex, regex, REG_EXTENDED) != 0) {
        LIBSIGSCAN_ERR("regcomp() returned an error code for pattern \"%s\"\n",
                       regex);
        return NULL;
    }

    FILE* fd = fopen("/proc/self/maps", "r");
    if (!fd) {
        LIBSIGSCAN_ERR("Couldn't open /proc/self/maps");
        return NULL;
    }

    /* For the first module. Start `ret' as NULL in case no module is valid. */
    LibsigscanModuleBounds* ret = NULL;
    LibsigscanModuleBounds* cur = ret;

    /* Buffers used in the loop by fgets() and sscanf() */
    static char line_buf[300];
    static char rwxp[5];
    static char pathname[200];

    while (fgets(line_buf, sizeof(line_buf), fd)) {
        pathname[0] = '\0';

        /* Scan the current line using sscanf(). We need to change address sizes
         * depending on the arch. */
        long unsigned start_num = 0, end_num = 0, offset = 0;
        int fmt_match_num =
          sscanf(line_buf, "%lx-%lx %4s %lx %*x:%*x %*d %s\n", &start_num,
                 &end_num, rwxp, &offset, pathname);

        if (fmt_match_num < 4) {
            LIBSIGSCAN_ERR("sscanf() didn't match the minimum fields (4) for "
                           "line:\n%s",
                           line_buf);
        }

        void* start_addr = (void*)start_num;
        void* end_addr   = (void*)end_num;

        /* Parse "rwxp". For now we only care about read permissions. */
        const bool is_readable = rwxp[0] == 'r';

        /* First, we make sure we got a name, and that it doesn't start with
         * '\0' or '['. Then, either we don't want to filter by module name
         * (regex is NULL) or we checked the regex and it matches. */
        const bool name_matches =
          fmt_match_num == 5 && pathname[0] != '\0' && pathname[0] != '[' &&
          (regex == NULL || libsigscan_regex(compiled_regex, pathname));

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

/* Search for pattern `ida' from `start' to `end'. */
static void* libsigscan_do_scan(void* start, void* end, const char* ida) {
    if (!start || !end) {
        LIBSIGSCAN_ERR("do_scan() got invalid start or end pointers");
        return NULL;
    }

    uint8_t* pattern;
    char* mask;
    libsigscan_ida2code(ida, &pattern, &mask);

    /* Current position in memory */
    uint8_t* start_ptr = (uint8_t*)start;
    uint8_t* mem_ptr   = start_ptr;

    int pat_pos  = 0;
    int mask_pos = 0;

    /* Iterate until we reach the end of the memory or the end of the pattern */
    while ((void*)mem_ptr < end && mask[mask_pos] != '\0') {
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

    free(pattern);
    free(mask);

    return ret;
}

/*----------------------------------------------------------------------------*/
/* Public functions */

/* Search for `ida_pattern' in modules matching `regex'. */
static void* sigscan_module(const char* regex, const char* ida_pattern) {
    /* Get a linked list of ModuleBounds, containing the start and end addresses
     * of all the regions whose name matches `regex'. */
    LibsigscanModuleBounds* bounds = libsigscan_get_module_bounds(regex);

    if (bounds == NULL)
        LIBSIGSCAN_ERR("Couldn't get any module bounds from /proc/self/maps");

    /* Iterate them, and scan each one until we find a match. */
    void* ret = NULL;
    for (LibsigscanModuleBounds* cur = bounds; cur != NULL; cur = cur->next) {
        void* cur_result =
          libsigscan_do_scan(cur->start, cur->end, ida_pattern);

        if (cur_result != NULL) {
            ret = cur_result;
            break;
        }
    }

    /* Free the ModuleBounds linked list */
    libsigscan_free_module_bounds(bounds);

    return ret;
}

/* Search for `ida_pattern' in all the loaded modules. */
static inline void* sigscan(const char* ida_pattern) {
    return sigscan_module(NULL, ida_pattern);
}

#endif /* LIBSIGSCAN_H_ */
