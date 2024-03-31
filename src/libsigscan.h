
#ifndef LIBSIGSCAN_H_
#define LIBSIGSCAN_H_ 1

#include <stddef.h>

/* Search for `ida_pattern' in the specified module. */
void* sigscan_module(const char* module, const char* ida_pattern);

/* Search for `ida_pattern' in all the loaded modules. */
static inline void* sigscan(const char* ida_pattern) {
    return sigscan_module(NULL, ida_pattern);
}

#endif /* LIBSIGSCAN_H_ */
