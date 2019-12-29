CFLAGS += -O2 -Wall -Wextra -Wpedantic -std=c99
CFLAGS += -Wshadow -Wundef -Wcast-qual -Wcast-align -Wstrict-prototypes
CFLAGS += -Wstrict-overflow -Wwrite-strings -Wunused-macros -Wredundant-decls
LDFLAGS += -Wl,--warn-common

.PHONY: all
all: librmap.a

librmap.a: librmap.a(rmap.o)

rmap.o: rmap.h

.PHONY: clean
clean:
	rm -f rmap.o librmap.a
