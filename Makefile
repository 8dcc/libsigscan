
CC=gcc
CFLAGS=-Wall -Wextra -Wpedantic
LDFLAGS=

OBJ_FILES=main.c.o
OBJS=$(addprefix obj/, $(OBJ_FILES))

BIN1=libsigscan-test.out
BIN2=libsigscan-test-external.out

#-------------------------------------------------------------------------------

.PHONY: clean all

all: $(BIN1) $(BIN2)

clean:
	rm -f $(BIN1) $(BIN2)

#-------------------------------------------------------------------------------

$(BIN1): src/main.c src/libsigscan.h
	$(CC) $(CFLAGS) -o $@ src/main.c $(LDFLAGS)

$(BIN2): src/external-test.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
