
CC=gcc
CFLAGS=-std=c99 -Wall -Wextra -Wpedantic
LDLIBS=

SRCS=libsigscan.c main.c external-test.c
OBJS=$(addprefix obj/, $(addsuffix .o, $(SRCS)))

BIN1=libsigscan-test.out
BIN2=libsigscan-test-external.out

#-------------------------------------------------------------------------------

.PHONY: all clean

all: $(BIN1) $(BIN2)

clean:
	rm -f $(OBJS)
	rm -f $(BIN1) $(BIN2)

#-------------------------------------------------------------------------------

$(BIN1): obj/main.c.o obj/libsigscan.c.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(BIN2): obj/external-test.c.o obj/libsigscan.c.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

obj/%.c.o : src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ -c $<
