/*
 * This file should be used for testing libsigscan on external processes.
 */

#include <stdio.h>

#define SECRET_SZ 100

/* This data would be in the application we are trying to scan. */
static unsigned char secret[SECRET_SZ] = { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
                                           0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB };

int main(int argc, char** argv) {
    (void)argc; /* Unused */

    printf("Hello from %s, this is my data:\n", argv[0]);

    for (int i = 0; i < 0xB; i++)
        printf("%02X ", secret[i]);

    printf("\n\nType anything to overwrite the data...\n");

    char c = 0;
    for (int i = 0; i < SECRET_SZ; i++) {
        if (i == 0 || c == '\n')
            printf("[%02d]> ", i);

        secret[i] = c = getchar();
    }

    printf("You have overwritten the entire array, exiting...\n");
    return 0;
}
