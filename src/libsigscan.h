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
#include <string.h> /* strstr() */
#include <stdlib.h> /* strtoull() */
#include <dirent.h> /* readdir() */
#include <regex.h>  /* regcomp(), regexec(), etc. */

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

/* Returns true if string `str` mathes regex pattern `pat`. Pattern uses BRE
 * syntax: https://www.gnu.org/software/sed/manual/html_node/BRE-syntax.html */
static bool libsigscan_regex(regex_t expr, const char* str) {
    int code = regexec(&expr, str, 0, NULL, 0);
    if (code > REG_NOMATCH) {
        char err[100];
        regerror(code, &expr, err, sizeof(err));
        fprintf(stderr, "libsigscan: regex: regexec returned an error: %s\n",
                err);
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
 * The format has to match this regex:
 *   [^\s]+-[^\s]+ [^\s]{4} [^\s]+ [^\s]+ [^\s]+\s+[^\s]*\n
 */
static LibsigscanModuleBounds* libsigscan_get_module_bounds(int pid,
                                                            const char* regex) {
    static regex_t compiled_regex;

    /* Compile regex pattern once here */
    if (regex != NULL && regcomp(&compiled_regex, regex, REG_EXTENDED) != 0) {
        fprintf(stderr,
                "libsigscan: regex: regcomp returned an error code for pattern "
                "\"%s\"\n",
                regex);
        return NULL;
    }

    /* Get the full path to /proc/PID/maps from the specified PID */
    static char maps_path[50] = "/proc/self/maps";
    if (pid != LIBSIGSCAN_PID_SELF)
        sprintf(maps_path, "/proc/%d/maps", pid);

    /* Open the maps file */
    FILE* fd = fopen(maps_path, "r");
    if (!fd)
        return NULL;

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

#ifdef LIBSIGSCAN_DEBUG
/* Print a linked list of ModuleBounds structures */
static void libsigscan_print_module_bounds(LibsigscanModuleBounds* bounds) {
    printf("[DEBUG] List of module bounds:\n");

    if (!bounds) {
        printf("(No module bounds)");
        return;
    }

    int i = 0;
    for (LibsigscanModuleBounds* cur = bounds; cur != NULL;
         cur                         = cur->next, i++)
        printf("[%02d] %p - %p\n", i, cur->start, cur->end);
    putchar('\n');
}
#endif

/* Used for getting the bytes from IDA patterns.
 * Converts: "E0" -> 224 */
static uint8_t libsigscan_hex_to_byte(const char* hex) {
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

/* Search for `pattern' from `start' to `end' inside the memory of `pid'. */
static void* libsigscan_pid_scan(int pid, void* start, void* end,
                                 const char* pattern) {
    if (!start || !end)
        return NULL;

    /* Skip preceding spaces from pattern, if any */
    while (*pattern == ' ')
        pattern++;

    /* TODO: Read from /proc/pid/mem */
    (void)pid;

    /* NOTE: This retarded void* -> char* cast is needed so g++ doesn't generate
     * a warning. */
    uint8_t* start_ptr = (uint8_t*)start;

    /* Current position in memory and current position in pattern */
    uint8_t* mem_ptr    = start_ptr;
    const char* pat_ptr = pattern;

    /* Iterate until we reach the end of the memory or the end of the pattern */
    while ((void*)mem_ptr < end && *pat_ptr != '\0') {
        /* Wildcard, always match */
        if (*pat_ptr == '?') {
            mem_ptr++;

            /* "A1 ?? ?? B2" -> "A1 ? ? B2" */
            while (*pat_ptr == '?')
                pat_ptr++;

            /* Remove trailing spaces after '?'
             * NOTE: I reused this code, but you could use `goto` */
            while (*pat_ptr == ' ')
                pat_ptr++;

            continue;
        }

        /* Convert "E0" into 224.
         * TODO: Would be better to only do this once at the start of the
         * function with some kind of ida2bytes function (We would need a mask
         * for the '?' vs. 0x3F). */
        uint8_t cur_byte = libsigscan_hex_to_byte(pat_ptr);

        if (*mem_ptr == cur_byte) {
            /* Found exact byte match in sequence, go to next byte in memory */
            mem_ptr++;

            /* Go to next byte separator in pattern (space) */
            while (*pat_ptr != ' ' && *pat_ptr != '\0')
                pat_ptr++;
        } else {
            /* Byte didn't match, check pattern from the begining on the next
             * position in memory */
            start_ptr++;
            mem_ptr = start_ptr;
            pat_ptr = pattern;
        }

        /* Skip trailing spaces */
        while (*pat_ptr == ' ')
            pat_ptr++;
    }

    /* If we reached end of pattern, return the match. Otherwise, NULL */
    return (*pat_ptr == '\0') ? start_ptr : NULL;
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

#ifdef LIBSIGSCAN_DEBUG
    libsigscan_print_module_bounds(bounds);
#endif

    /* Iterate them, and scan each one until we find a match. */
    void* ret = NULL;
    for (LibsigscanModuleBounds* cur = bounds; cur != NULL; cur = cur->next) {
        void* cur_result =
          libsigscan_pid_scan(pid, cur->start, cur->end, ida_pattern);

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
