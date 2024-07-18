# Can be defined to allow a custom implementation of rmap_crc_calculate()
ifdef RMAP_CUSTOM_CRC_IMPLEMENTATION
CPPFLAGS += -DRMAP_CUSTOM_CRC_IMPLEMENTATION
endif
CPPFLAGS += -DNDEBUG -I.
CFLAGS += -O2 -g -Wall -Wextra -Wpedantic -std=c99
CFLAGS += -Wshadow -Wundef -Wcast-qual -Wcast-align -Wstrict-prototypes
CFLAGS += -Wstrict-overflow -Wwrite-strings -Wunused-macros -Wredundant-decls
LDFLAGS += -Wl,--warn-common

EXAMPLES = \
	examples/creating_a_write_command \
	examples/creating_a_reply_from_a_command \
	examples/print_packet_descriptions

.PHONY: default
default: librmap.a

librmap.a: rmap.o
	$(AR) $(ARFLAGS) $@ $^

rmap.o: rmap.h

.PHONY: test
test:
	$(MAKE) -C test test

.PHONY: coverage
coverage:
	$(MAKE) -C test coverage

.PHONY: examples
examples: $(EXAMPLES)

$(EXAMPLES): librmap.a

.PHONY: clean
clean:
	rm -f rmap.o librmap.a $(EXAMPLES:%=%.o) $(EXAMPLES)
	rm -rf html
	$(MAKE) -C test clean
