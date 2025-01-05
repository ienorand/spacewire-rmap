/** Example showing parsing and printing of RMAP commands and replies.
 *
 * This example shows how RMAP commands and replies can be parsed and printed
 * using the spacewire-rmap library functions.
 *
 * If stdin is not a terminal, packet data is read from stdin as raw binary
 * bytes.
 *
 * If stdin is a terminal, a predefined set of source patterns are used as
 * input packets.
 *
 * Source patterns 0-3 corresponds to the RMAP CRC test patterns from section
 * A.4 in the RMAP standard (ECSS‐E‐ST‐50‐52C 5 February 2010).
 */

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <io.h>
#define isatty _isatty
#else
#include <unistd.h>
#endif

#include "rmap.h"

struct pattern {
    const uint8_t *const data;
    size_t size;
};

static const uint8_t pattern0[] = {
    0xFE, 0x01, 0x6C, 0x00, 0x67, 0x00, 0x00, 0x00, 0xA0, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x10, 0x9F, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
    0xCD, 0xEF, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x56,
};

static const uint8_t pattern0_reply[] = {
    0x67,
    0x01,
    0x2C,
    0x00,
    0xFE,
    0x00,
    0x00,
    0xED,
};

static const uint8_t pattern1[] = {
    0xFE,
    0x01,
    0x4C,
    0x00,
    0x67,
    0x00,
    0x01,
    0x00,
    0xA0,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x10,
    0xC9,
};

static const uint8_t pattern1_reply[] = {
    0x67, 0x01, 0x0C, 0x00, 0xFE, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x10, 0x6D, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x56,
};

static const uint8_t pattern2[] = {
    0xFE, 0x01, 0x6E, 0x00, 0x00, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
    0x00, 0x67, 0x00, 0x02, 0x00, 0xA0, 0x00, 0x00, 0x10, 0x00, 0x00,
    0x10, 0x7F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8,
    0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB4,
};

static const uint8_t pattern2_reply[] = {
    0x67,
    0x01,
    0x2E,
    0x00,
    0xFE,
    0x00,
    0x02,
    0x1D,
};

static const uint8_t pattern3[] = {
    0xFE, 0x01, 0x4D, 0x00, 0x99, 0xAA, 0xBB, 0xCC, 0x67, 0x00,
    0x03, 0x00, 0xA0, 0x00, 0x00, 0x10, 0x00, 0x00, 0x10, 0xF7,
};

static const uint8_t pattern3_reply[] = {
    0x67, 0x01, 0x0D, 0x00, 0xFE, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x10, 0x52, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB4,
};

static const uint8_t pattern4[] = {
    0xFE, 0x01, 0x5C, 0x00, 0x67, 0x00, 0x04, 0x00, 0xA0, 0x00, 0x00, 0x10,
    0x00, 0x00, 0x06, 0x9D, 0xC0, 0x18, 0x02, 0xF0, 0x3C, 0x03, 0xE3,
};

static const uint8_t pattern4_reply[] = {
    0x67,
    0x01,
    0x1C,
    0x00,
    0xFE,
    0x00,
    0x04,
    0x00,
    0x00,
    0x00,
    0x03,
    0x4F,
    0xA0,
    0xA1,
    0xA2,
    0xD7,
};

static const uint8_t pattern5[] = {
    0xFE, 0x01, 0x5D, 0x00, 0x00, 0x00, 0x00, 0x88, 0x67, 0x00,
    0x05, 0x00, 0xA0, 0x00, 0x00, 0x10, 0x00, 0x00, 0x08, 0xC6,
    0x07, 0x02, 0xA0, 0x00, 0x0F, 0x83, 0xE0, 0xFF, 0x1D,
};

static const uint8_t pattern5_reply[] = {
    0x67,
    0x01,
    0x1D,
    0x00,
    0xFE,
    0x00,
    0x05,
    0x00,
    0x00,
    0x00,
    0x04,
    0xFF,
    0xE0,
    0x99,
    0xA2,
    0xA3,
    0x7D,
};

static const struct pattern patterns[] = {
    {
        .data = pattern0,
        .size = sizeof(pattern0),
    },
    {
        .data = pattern0_reply,
        .size = sizeof(pattern0_reply),
    },
    {
        .data = pattern1,
        .size = sizeof(pattern1),
    },
    {
        .data = pattern1_reply,
        .size = sizeof(pattern1_reply),
    },
    {
        .data = pattern2,
        .size = sizeof(pattern2),
    },
    {
        .data = pattern2_reply,
        .size = sizeof(pattern2_reply),
    },
    {
        .data = pattern3,
        .size = sizeof(pattern3),
    },
    {
        .data = pattern3_reply,
        .size = sizeof(pattern3_reply),
    },
    {
        .data = pattern4,
        .size = sizeof(pattern4),
    },
    {
        .data = pattern4_reply,
        .size = sizeof(pattern4_reply),
    },
    {
        .data = pattern5,
        .size = sizeof(pattern5),
    },
    {
        .data = pattern5_reply,
        .size = sizeof(pattern5_reply),
    },
};

static void print_data(const void *const raw, const size_t size)
{
    const uint8_t *const raw_bytes = raw;
    for (size_t i = 0; i < size; ++i) {
        printf("0x%02X", raw_bytes[i]);
        if (i < size) {
            printf(" ");
        }
    }
    printf("\n");
}

static void print_command_description(const void *const raw, const size_t size)
{
    enum rmap_status rmap_status;

    uint8_t reply_address[RMAP_REPLY_ADDRESS_LENGTH_MAX];
    size_t reply_address_size;

    if (rmap_is_write(raw)) {
        printf(" write");
        if (rmap_is_with_reply(raw)) {
            printf("-with-reply");
        }
    } else if (rmap_is_rmw(raw)) {
        printf(" RMW");
    } else {
        printf(" read");
    }

    printf(" command:\n");

    printf(
        "  Target logical address: 0x%02X\n",
        rmap_get_target_logical_address(raw));

    printf("  Key: 0x%02X\n", rmap_get_key(raw));

    rmap_status = rmap_get_reply_address(
        reply_address,
        &reply_address_size,
        sizeof(reply_address),
        raw);
    assert(rmap_status == RMAP_OK);
    (void)rmap_status;

    printf("  Reply address: ");
    print_data(reply_address, reply_address_size);

    printf(
        "  Initiator logical address: 0x%02X\n",
        rmap_get_initiator_logical_address(raw));

    printf(
        "  Transaction identifier: 0x%04X\n",
        rmap_get_transaction_identifier(raw));

    printf("  Extended address: 0x%02X\n", rmap_get_extended_address(raw));

    printf("  Address: 0x%08" PRIX32 "\n", rmap_get_address(raw));

    printf("  Data length: 0x%06" PRIX32 "\n", rmap_get_data_length(raw));

    if (!rmap_is_write(raw) && !rmap_is_rmw(raw)) {
        /* Read. */
        return;
    }

    /* Write or RMW. */

    const uint8_t *const raw_bytes = raw;
    const size_t data_offset = rmap_calculate_header_size(raw);

    rmap_status = rmap_verify_data(raw, size);
    if (rmap_status != RMAP_OK) {
        printf("  Invalid data: %s:\n", rmap_status_text(rmap_status));
        printf("  Data with data CRC: ");
        print_data(raw_bytes + data_offset, size - data_offset);
        return;
    }

    if (rmap_is_write(raw)) {
        printf("  Data: ");
        print_data(raw_bytes + data_offset, rmap_get_data_length(raw));
        return;
    }

    /* RMW. */

    printf("  Data: ");
    print_data(raw_bytes + data_offset, rmap_get_data_length(raw) / 2);
    printf("  Mask: ");
    print_data(
        raw_bytes + data_offset + rmap_get_data_length(raw) / 2,
        rmap_get_data_length(raw) / 2);
}

static void print_reply_description(const void *const raw, const size_t size)
{
    if (rmap_is_write(raw)) {
        printf(" write");
    } else if (rmap_is_rmw(raw)) {
        printf(" RMW");
    } else {
        printf(" read");
    }

    printf(" reply:\n");

    printf(
        "  Initiator logical address: 0x%02X\n",
        rmap_get_initiator_logical_address(raw));

    printf(
        "  Status: %s (0x%02X)\n",
        rmap_status_text(rmap_get_status(raw)),
        rmap_get_status(raw));

    printf(
        "  Target logical address: 0x%02X\n",
        rmap_get_target_logical_address(raw));

    printf(
        "  Transaction identifier: 0x%04X\n",
        rmap_get_transaction_identifier(raw));

    if (rmap_is_write(raw)) {
        return;
    }

    /* Read or RMW. */

    printf("  Data length: 0x%06" PRIX32 "\n", rmap_get_data_length(raw));

    const uint8_t *const raw_bytes = raw;
    const size_t data_offset = rmap_calculate_header_size(raw);

    const enum rmap_status rmap_status = rmap_verify_data(raw, size);
    if (rmap_status != RMAP_OK) {
        printf("  Invalid data: %s:\n", rmap_status_text(rmap_status));
        printf("  Data with data CRC: ");
        print_data(raw_bytes + data_offset, size - data_offset);
        return;
    }

    printf("  Data: ");
    print_data(raw_bytes + data_offset, rmap_get_data_length(raw));
}

static void print_packet_description(const void *const raw, const size_t size)
{
    enum rmap_status rmap_status;

    rmap_status = rmap_verify_header_integrity(raw, size);
    if (rmap_status != RMAP_OK) {
        printf("Non-RMAP packet: %s\n", rmap_status_text(rmap_status));
        return;
    } else {
        printf("RMAP");
    }

    rmap_status = rmap_verify_header_instruction(raw);
    if (rmap_status != RMAP_OK) {
        printf(
            " packet with invalid header: %s\n",
            rmap_status_text(rmap_status));
        return;
    }

    if (!rmap_is_rmw(raw)) {
        /* Write or Read. */

        if (rmap_is_verify_data_before_write(raw)) {
            printf(" verified");
        } else {
            printf(" non-verified");
        }

        if (rmap_is_increment_address(raw)) {
            printf(" incrementing");
        } else {
            printf(" non-incrementing");
        }
    }

    if (rmap_is_command(raw)) {
        print_command_description(raw, size);
        return;
    }

    print_reply_description(raw, size);
}

int main(void)
{
    if (!isatty(0)) {
        FILE *const binary_stdin = freopen(NULL, "rb", stdin);
        if (!binary_stdin) {
            perror("Failed to open stdin as binary");
            exit(EXIT_FAILURE);
        }
        static uint8_t buf[RMAP_HEADER_SIZE_MAX + RMAP_DATA_LENGTH_MAX + 1];
        const size_t size = fread(buf, 1, sizeof(buf), binary_stdin);
        print_data(buf, size);
        print_packet_description(buf, size);
        exit(EXIT_SUCCESS);
    }

    /* stdin is a terminal, print hardcoded packet examples. */

    for (size_t i = 0; i < sizeof(patterns) / sizeof(*patterns); ++i) {
        print_data(patterns[i].data, patterns[i].size);
        print_packet_description(patterns[i].data, patterns[i].size);
        printf("\n");
    }
}
