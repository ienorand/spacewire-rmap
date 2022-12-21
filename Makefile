CPPFLAGS += -DNDEBUG -I.
CFLAGS += -O2 -g -Wall -Wextra -Wpedantic -std=c99
CFLAGS += -Wshadow -Wundef -Wcast-qual -Wcast-align -Wstrict-prototypes
CFLAGS += -Wstrict-overflow -Wwrite-strings -Wunused-macros -Wredundant-decls
LDFLAGS += -Wl,--warn-common

EXAMPLES = \
	examples/creating_a_write_command \
	examples/creating_a_reply_from_a_command

.PHONY: default
default: librmap.a

librmap.a: rmap.o
	$(AR) $(ARFLAGS) $@ $^

rmap.o: rmap.h

.PHONY: test
test:
	$(MAKE) -C test test

.PHONY: examples
examples: $(EXAMPLES)

$(EXAMPLES): librmap.a

.PHONY: clean
clean:
	rm -f rmap.o librmap.a $(EXAMPLES:%=%.o) $(EXAMPLES)
	$(MAKE) -C test clean
