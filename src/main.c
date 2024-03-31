
#include <stdio.h>
#include "libsigscan.h"

/* This data would be in the application we are trying to scan. */
static const unsigned char secret[] = { 0xDE, 0xAD, 0xBE, 0xEF,
                                        0x0B, 0xAD, 0xCA, 0xFE };

static void echo_maps(void) {
    printf("Dumping /proc/self/maps:\n");
    FILE* fd = fopen("/proc/self/maps", "r");
    int c;
    while ((c = fgetc(fd)) != EOF)
        putchar(c);
    fclose(fd);
    putchar('\n');
}

int main(void) {
    /*------------------------------------------------------------------------*/
    /* Code from the main program */

    printf("I am the main program, and this is my data at %p:\n", secret);
    for (size_t i = 0; i < sizeof(secret); i++)
        printf("0x%02X ", secret[i]);
    printf("\n\n");

    /*------------------------------------------------------------------------*/
    /* Information to make sure the test was fine */

    echo_maps();

    /*------------------------------------------------------------------------*/
    /* The following code should be ran after injecting to the target process.
     * We don't inject in this example because we are looking in our own
     * process.
     *
     * NOTE: The signatures have to be in IDA format. See also:
     * https://github.com/ajkhoury/SigMaker-x64 */
    const char* signature = "DE AD BE EF ? ? CA FE";
    void* match;

    /* Look for those bytes in all loaded modules. */
    match = sigscan(signature);
    printf("Searching in all modules: %p\n", match);

    if (match != NULL) {
        unsigned char* as_bytes = (unsigned char*)match;
        printf("First %ld bytes: ", sizeof(secret));
        for (size_t i = 0; i < sizeof(secret); i++)
            printf("0x%02X ", as_bytes[i]);
        putchar('\n');
    }

    /* Search only in this module. */
    match = sigscan_module("/usr/lib/libc.so.6", signature);
    printf("Searching in a different module: %p\n", match);

    /* Invalid module, just returns NULL */
    match = sigscan_module("/usr/lib/INVALID.so", signature);
    printf("Searching in an invalid module: %p\n", match);

    return 0;
}
