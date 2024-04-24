
CC=gcc
CFLAGS=-Wall -Wextra -Wpedantic
LDFLAGS=

BIN=libsigscan-test.out

#-------------------------------------------------------------------------------

.PHONY: clean all

all: $(BIN)

clean:
	rm -f $(BIN)

#-------------------------------------------------------------------------------

$(BIN): src/main.c src/libsigscan.h
	$(CC) $(CFLAGS) -o $@ src/main.c $(LDFLAGS)
