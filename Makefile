
CC=gcc
CFLAGS=-std=gnu99 -Wall -Wextra -Wpedantic
LDLIBS=

BIN=libsigscan-test.out

SRCS=libsigscan.c main.c
OBJS=$(addprefix obj/, $(addsuffix .o, $(SRCS)))

#-------------------------------------------------------------------------------

.PHONY: all clean

all: $(BIN)

clean:
	rm -f $(OBJS)
	rm -f $(BIN)

#-------------------------------------------------------------------------------

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

obj/%.c.o : src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ -c $<
