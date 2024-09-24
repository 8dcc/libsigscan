/*
 * libsigscan.c - Simple C/C++ library for signature scanning on Linux.
 * See: https://github.com/8dcc/libsigscan
 * Copyright (C) 2024 8dcc
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>  /* fopen(), FILE* */
#include <stdlib.h> /* strtoull() */
#include <ctype.h>  /* isspace() */
#include <regex.h>  /* regcomp(), regexec(), etc. */

/* NOTE: Remember to change the path if you move the header */
#include "libsigscan.h"

/*----------------------------------------------------------------------------*/
/* Private macros */

#ifdef LIBSIGSCAN_DEBUG
#define ERR(...)                         \
    do {                                 \
        fprintf(stderr, "libsigscan: "); \
        fprintf(stderr, __VA_ARGS__);    \
        fputc('\n', stderr);             \
    } while (0)
#else
#define ERR(...) \
    do {         \
    } while (0)
#endif

/*----------------------------------------------------------------------------*/
/* Private functions */

/*
 * Returns true if string `str' mathes regex pattern `pat'.
 */
static bool does_regex_match(regex_t expr, const char* str) {
    int code = regexec(&expr, str, 0, NULL, 0);
    if (code > REG_NOMATCH) {
        char err[100];
        regerror(code, &expr, err, sizeof(err));
        ERR("regexec() returned an error: %s\n", err);
        return false;
    }

    return code == REG_NOERROR;
}

/*
 * Convert a hexadecimal string representing a byte into the actual byte
 * value. For example: "E0" -> 224.
 *
 * Used for getting the bytes from IDA patterns.
 */
static uint8_t hex2byte(const char* hex) {
    int result = 0;

    /* Skip leading spaces, if any */
    while (isspace(*hex))
        hex++;

    /* Store a byte (two digits of string) */
    for (int i = 0; i < 2 && hex[i] != '\0'; i++) {
        const char c = hex[i];

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
        result <<= 4;
        result |= n & 0xF;
    }

    return result & 0xFF;
}

/*
 * Convert `ida' signature to code + mask format. Allocate `code_ptr' and
 * `mask_ptr'.
 *
 * IDA format:  "FF ? ? 89"
 * Code format: "\xFF\x00\x00\x89"
 * Mask format: "x??x"
 */
static void ida2code(const char* ida, uint8_t** code_ptr, char** mask_ptr) {
    /*
     * The `dst_sz' and `dst_i' variables will be used for both `code' and
     * `mask' arrays.
     */
    size_t dst_sz = 100;
    *code_ptr     = (uint8_t*)malloc(dst_sz);
    *mask_ptr     = (char*)malloc(dst_sz);
    if (*code_ptr == NULL || *mask_ptr == NULL) {
        ERR("malloc() returned NULL");
        return;
    }

    /* Skip leading spaces from pattern, if any */
    while (isspace(*ida))
        ida++;

    size_t dst_i;
    for (dst_i = 0; *ida != '\0'; dst_i++) {
        if (dst_i >= dst_sz - 1) {
            dst_sz += 100;
            *code_ptr = (uint8_t*)realloc(*code_ptr, dst_sz);
            *mask_ptr = (char*)realloc(*mask_ptr, dst_sz);
        }

        if (*ida == '?') {
            (*code_ptr)[dst_i] = 0x00;
            (*mask_ptr)[dst_i] = '?';

#ifdef LIBSIGSCAN_MULTIPLE_WILDCARDS
            /* "A1 ?? ?? B2" -> "A1 ? ? B2" */
            while (*ida == '?')
#endif
                ida++;
        } else {
            /* Convert "E0" to 224 */
            (*code_ptr)[dst_i] = hex2byte(ida);
            (*mask_ptr)[dst_i] = 'x';

            /* Go to next byte separator in pattern (space) */
            while (!isspace(*ida) && *ida != '\0')
                ida++;
        }

        /* Skip trailing spaces */
        while (isspace(*ida))
            ida++;
    }

    /*
     * Indicate the end of the pattern in the `mask', since 0x00 is a valid
     * byte in the `code' array.
     */
    (*mask_ptr)[dst_i] = '\0';
}

/* Search for pattern `ida' from `start' to `end'. */
static void* do_scan(void* start, void* end, const char* ida) {
    if (!start || !end) {
        ERR("do_scan() got invalid start or end pointers");
        return NULL;
    }

    uint8_t* pattern;
    char* mask;
    ida2code(ida, &pattern, &mask);

    /* Current position in memory */
    uint8_t* start_ptr = (uint8_t*)start;
    uint8_t* mem_ptr   = start_ptr;

    int pat_pos  = 0;
    int mask_pos = 0;

    /* Iterate until we reach the end of the memory or the end of the pattern */
    while ((void*)mem_ptr < end && mask[mask_pos] != '\0') {
        if (mask[mask_pos] == '?' || *mem_ptr == pattern[pat_pos]) {
            /*
             * Either there was a wildcard on the mask, or we found exact byte
             * match with the pattern. Go to next byte in memory.
             */
            mem_ptr++;
            pat_pos++;
            mask_pos++;
        } else {
            /*
             * Byte didn't match, check pattern from the begining on the next
             * position in memory.
             */
            start_ptr++;
            mem_ptr  = start_ptr;
            pat_pos  = 0;
            mask_pos = 0;
        }
    }

    /*
     * If we reached end of the mask (i.e. pattern), return the match.
     * Otherwise, NULL.
     */
    void* ret = (mask[mask_pos] == '\0') ? start_ptr : NULL;

    free(pattern);
    free(mask);

    return ret;
}

/*----------------------------------------------------------------------------*/
/* Public functions */

SigscanModuleBounds* sigscan_get_module_bounds(const char* regex) {
    static regex_t compiled_regex;

    /* Compile regex pattern once here */
    if (regex != NULL && regcomp(&compiled_regex, regex, REG_EXTENDED) != 0) {
        ERR("regcomp() returned an error code for pattern \"%s\"\n", regex);
        return NULL;
    }

    FILE* fd = fopen("/proc/self/maps", "r");
    if (!fd) {
        ERR("Couldn't open /proc/self/maps");
        return NULL;
    }

    /* For the first module. Start `ret' as NULL in case no module is valid. */
    SigscanModuleBounds* ret = NULL;
    SigscanModuleBounds* cur = ret;

    /* Buffers used in the loop by fgets() and sscanf() */
    static char line_buf[300];
    static char rwxp[5];
    static char pathname[200];

    while (fgets(line_buf, sizeof(line_buf), fd)) {
        pathname[0] = '\0';

        /*
         * Scan the current line using `sscanf'. We need to change address sizes
         * depending on the arch.
         */
        long unsigned start_num = 0, end_num = 0, offset = 0;
        int fmt_match_num =
          sscanf(line_buf, "%lx-%lx %4s %lx %*x:%*x %*d %200[^\n]\n",
                 &start_num, &end_num, rwxp, &offset, pathname);

        if (fmt_match_num < 4) {
            ERR("sscanf() didn't match the minimum fields (4) for "
                "line:\n%s",
                line_buf);
        }

        void* start_addr = (void*)start_num;
        void* end_addr   = (void*)end_num;

        /* Parse "rwxp". For now we only care about read permissions. */
        const bool is_readable = rwxp[0] == 'r';

        /*
         * First, we make sure we got a name, and that it doesn't start with
         * '\0' or '['. Then, either we don't want to filter by module name
         * (regex is NULL) or we checked the regex and it matches.
         */
        const bool name_matches =
          fmt_match_num == 5 && pathname[0] != '\0' && pathname[0] != '[' &&
          (regex == NULL || does_regex_match(compiled_regex, pathname));

        /* We can read it, and it's the module we are looking for. */
        if (is_readable && name_matches) {
            if (cur == NULL) {
                /* Allocate the first bounds struct
                 * FIXME: Use dummy method. */
                cur = (SigscanModuleBounds*)malloc(sizeof(SigscanModuleBounds));

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
                cur->next =
                  (SigscanModuleBounds*)malloc(sizeof(SigscanModuleBounds));

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

void sigscan_free_module_bounds(SigscanModuleBounds* bounds) {
    SigscanModuleBounds* cur = bounds;
    while (cur != NULL) {
        SigscanModuleBounds* next = cur->next;
        free(cur);
        cur = next;
    }
}

void* sigscan_module(const char* regex, const char* ida_pattern) {
    /*
     * Get a linked list of `SigscanModuleBounds' structures, containing the
     * start and end addresses of all the regions whose name matches `regex'.
     */
    SigscanModuleBounds* bounds = sigscan_get_module_bounds(regex);

    if (bounds == NULL) {
        ERR("Couldn't get any module bounds matching regex \"%s\" "
            "in /proc/self/maps",
            regex);
        return NULL;
    }

    /* Iterate them, and scan each one until we find a match. */
    void* ret = NULL;
    for (SigscanModuleBounds* cur = bounds; cur != NULL; cur = cur->next) {
        void* cur_result = do_scan(cur->start, cur->end, ida_pattern);

        if (cur_result != NULL) {
            ret = cur_result;
            break;
        }
    }

    /* Free the `SigscanModuleBounds' linked list. */
    sigscan_free_module_bounds(bounds);

    return ret;
}
