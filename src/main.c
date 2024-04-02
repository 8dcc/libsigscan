
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
    const char* module_regex;
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
    module_regex = "^.*libsigscan-test\\.out$";
    match        = sigscan_module(module_regex, signature);
    printf("Searching in all modules matching regex \"%s\": %p\n", module_regex,
           match);

    /* Invalid module, just returns NULL */
    module_regex = "^INVALID$";
    match        = sigscan_module(module_regex, signature);
    printf("Searching in all modules matching regex \"%s\": %p\n", module_regex,
           match);

    return 0;
}
