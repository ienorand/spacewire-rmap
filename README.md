# spacewire-rmap

spacewire-rmap is a C library for serializing and deserializing SpaceWire RMAP
commands and replies, it is intended to be useful when handling SpaceWire RMAP
in software.

[![build](https://github.com/ienorand/spacewire-rmap/actions/workflows/build.yml/badge.svg)](https://github.com/ienorand/spacewire-rmap/actions/workflows/build.yml)
[![test](https://github.com/ienorand/spacewire-rmap/actions/workflows/test.yml/badge.svg)](https://github.com/ienorand/spacewire-rmap/actions/workflows/test.yml)

## License

spacewire-rmap is provided under the BSD-2-Clause license, see
[**`COPYING`**](COPYING) for more information.

## Compiling

Running the default make target will produce a **`librmap.a`** file for linking.

## Tests

Tests are implemented using the
[googletest](https://github.com/google/googletest) framework.

In order to compile and run the test, the `test` make target can be used
from the root directory.

Alternatively, the test-suite binary can be compiled via the default make
target in the **`test/`** subdirectory and the test-suite can be run by
executing the resulting **`test/rmap_test`** binary.

## Usage

### Error Reporting

Errors are reported using the custom `enum rmap_status` type. The enum constant
`RMAP_OK` indicates success.

In order to produce a string representation of enum constants, the
`rmap_status_text()` function can be used.

### Pre-Conditions for Access Functions

Most access functions provided by this library requires that the data they are
applied to already have been confirmed to contain an RMAP header, otherwise
this will result in undefined behaviour. Here, an "RMAP header" is defined as:

*   The part of an RMAP command starting with the target logical address and
    ending with the header CRC.
*   The part of an RMAP reply starting with the initiator logical address and
    ending with the header CRC.

Hence if an RMAP packet contains a target spacewire address or reply spacewire
address before the header, an offset needs to be used.

Additionally, many access functions are only valid for a limited set of RMAP
header types, based on if the field being accessed are available in the given
header type or not. Using access functions on RMAP header types for which they
are not valid will result in undefined behaviour.

### Validating a Packet

When processing a potential RMAP packet from unknown data, it must first be
verified to contain a complete RMAP header using
`rmap_verify_header_integrity()` before any of the other functions for
accessing the header may be used.

The normal procedure for validating a packet based on unknown data is to use
the following functions in sequence:

* `rmap_verify_header_integrity()`
* `rmap_verify_header_instruction()`

Failure when verifying the header integrity should result in the packet being
discarded according to the RMAP standard.

Failure when verifying the header instruction should sometimes result in the
packet being discarded and sometimes result in a reply being sent according to
the RMAP standard.

#### Header Type

In order to determine the RMAP header type, the following functions are
available:

*   `rmap_is_command()`
    * `true` indicates a command
    * `false` indicates a reply
*   `rmap_is_write()`
    * `true` indicates a write command or write reply
    * `false` indicates a read command, RMW command, read reply, or RMW reply
*   `rmap_is_verify_data_before_write()`
*   `rmap_is_with_reply()`
*   `rmap_is_increment_address()`
*   `rmap_is_rmw()`

#### Data

For RMAP packets which contain data, the `rmap_verify_data()` function is
available for verifying the data.

Failure when verifying the data should result in a reply being sent according
to the RMAP standard.

### Creating a Packet

When creating an RMAP header, it must first be initialized using one of the
following functions

*   `rmap_initialize_header()`
*   `rmap_initialize_header_before()`
*   `rmap_create_success_reply_from_command()`
*   `rmap_create_success_reply_from_command_before()`

before any of the other functions for accessing the header may be used.

The basic procedure for creating an RMAP packet using this library is:

* Add target or reply spacewire address if applicable
* Initialize the RMAP header using `rmap_initialize_header()`
* Set remaining RMAP header fields using access functions
* Add data and CRC after the header if applicable

The function `rmap_initialize_header_before()` is a convenience function which
allows initializing an RMAP header before already existing data, without
needing to calculate the header size beforehand.

#### Definition of "Initializing"

The `rmap_initialize_header()` and `rmap_initialize_header_before()` functions
initialize an RMAP header by setting the protocol and instruction fields; the
protocol field indicates that the packet is an RMAP packet and the instruction
field fully defines the format and size of the RMAP header.

Initializing the RMAP header is sufficient to allow setting all remaining
fields in the header using access functions.

#### Reply

When creating an RMAP reply, the convenience functions
`rmap_create_success_reply_from_command()` and
`rmap_create_success_reply_from_command_before()` can be used to directly
create a reply matching the source command.

The reply spacewire address is part of the RMAP reply and will be added
immediately before the RMAP header.

The RMAP header is set to correspond to a reply resulting from a successful
processing of the source command. It is expected that the RMAP header will be
updated to match the actual result of the command processing; the success reply
may be used as a template for an error reply.

If the RMAP packet is a type which contains data, this must be added separately
and the data length must be updated.

When using the `rmap_create_success_reply_from_command()` function the data and
CRC is normally added last.

The `rmap_create_success_reply_from_command_before()` function allows the data
and CRC to be added first, with the rest of the packet being created
immediately before the existing data.

### Custom CRC implementation support

It is possible to use a different CRC implementation instead of the table-based
implementation normally defined in the library via the following steps:

*   Use the `RMAP_CUSTOM_CRC_IMPLEMENTATION` make flag when compiling the
    library to remove the included definition of the `rmap_crc_calculate()`
    function.
*   Provide a compatible definition of the `rmap_crc_calculate()` function at
    link time.

#### Disabling CRC

It is possible to effectively disable the CRC calculation and verification by
providing a custom definition of the `rmap_crc_calculate()` function which
always returns `0`.

This will make the CRC verification always succeed; the library includes the
trailing reference CRC when performing the verification calculation, which will
always produce a `0` result (for data without errors) based on the RMAP CRC
algorithm.

Using a `0`-return `rmap_crc_calculate()` function will result in RMAP packets
being created with a `0` header (and data) CRC.

This can be useful if CRC calculation and verification is handled by other
means.

### Examples

Examples showing creation of RMAP commands and replies using this library are
available in the following files:

*   [**`examples/creating_a_write_command.c`**](examples/creating_a_write_command.c)
*   [**`examples/creating_a_reply_from_a_command.c`**](examples/creating_a_reply_from_a_command.c)

## Assertions

This library uses the **`assert()`** macro to verify library-internal pre- and
post-conditions, these assertions are intended to only be used during the
verification of the library itself and are therefore removed via the
**`NDEBUG`** macro in the default build.
