CFLAGS += -O2 -Wall -Wextra -Wpedantic -std=c99
LDFLAGS += -Wl,--warn-common

.PHONY: all
all: librmap.a

librmap.a: librmap.a(rmap.o)

rmap.o: rmap.h

.PHONY: clean
clean:
	rm -f rmap.o librmap.a
