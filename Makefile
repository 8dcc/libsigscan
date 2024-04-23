
CC=gcc
CFLAGS=-Wall -Wextra
LDFLAGS=

BIN=libsigscan-test.out

#-------------------------------------------------------------------------------

.PHONY: clean all

all: $(BIN)

clean:
	rm -f $(BIN)

#-------------------------------------------------------------------------------

$(BIN): src/main.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
