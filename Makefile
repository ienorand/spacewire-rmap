# Can be defined to allow a custom implementation of rmap_crc_calculate()
ifdef RMAP_CUSTOM_CRC_IMPLEMENTATION
CPPFLAGS += -DRMAP_CUSTOM_CRC_IMPLEMENTATION
endif
CPPFLAGS += -I.
CFLAGS += -O2 -g -Wall -Wextra -Wpedantic -std=c99
CFLAGS += -Wshadow -Wundef -Wcast-qual -Wcast-align -Wstrict-prototypes
CFLAGS += -Wstrict-overflow -Wwrite-strings -Wunused-macros -Wredundant-decls
LDFLAGS += -Wl,--warn-common

RMAP_EXAMPLES = \
	examples/creating_a_write_command \
	examples/creating_a_reply_from_a_command \
	examples/print_packet_descriptions

NODE_EXAMPLES = \
	examples/target_and_initiator_node \
	examples/target_node

EXAMPLES = $(RMAP_EXAMPLES) $(NODE_EXAMPLES)

.PHONY: default
default: librmap.a librmap-node.a

librmap.a: rmap.o
	$(AR) $(ARFLAGS) $@ $^

librmap-node.a: rmap.o node.o
	$(AR) $(ARFLAGS) $@ $^

rmap.o: rmap.c rmap.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -DNDEBUG -c -o $@ $<

node.o: node.c node.h rmap.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -DNDEBUG -c -o $@ $<

.PHONY: test
test:
	$(MAKE) -C test test

.PHONY: coverage
coverage:
	$(MAKE) -C test coverage

.PHONY: examples
examples: $(EXAMPLES)

$(RMAP_EXAMPLES): librmap.a

$(NODE_EXAMPLES): librmap-node.a

.PHONY: clean
clean:
	rm -f rmap.o node.o librmap.a librmap-node.a $(EXAMPLES:%=%.o) $(EXAMPLES)
	rm -rf html
	$(MAKE) -C test clean
