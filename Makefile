CFLAGS += -Wall -Wextra -Wpedantic -std=c99
LDFLAGS += -Wl,--warn-common

.PHONY: all
all: librmap.a

librmap.a: librmap.a(rmap.o)

rmap.o: rmap.h

clean:
	rm -f rmap.o librmap.a
