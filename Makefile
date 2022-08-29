CPPFLAGS += -DNDEBUG
CFLAGS += -O2 -g -Wall -Wextra -Wpedantic -std=c99
CFLAGS += -Wshadow -Wundef -Wcast-qual -Wcast-align -Wstrict-prototypes
CFLAGS += -Wstrict-overflow -Wwrite-strings -Wunused-macros -Wredundant-decls
LDFLAGS += -Wl,--warn-common

.PHONY: default
default: librmap.a

librmap.a: rmap.o
	$(AR) $(ARFLAGS) $@ $^

rmap.o: rmap.h

.PHONY: test
test:
	$(MAKE) -C test test

.PHONY: clean
clean:
	rm -f rmap.o librmap.a
	$(MAKE) -C test clean
