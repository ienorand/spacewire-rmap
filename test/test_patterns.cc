#include "test_patterns.h"

/* RMAP test patterns from ECSS‐E‐ST‐50‐52C, 5 February 2010. */

const struct test_pattern
    test_pattern0_unverified_incrementing_write_with_reply = {
        .data =
            {
                /* Target Logical Address */
                0xFE,
                /* Protocol Identifier */
                0x01,
                /* Instruction */
                0x6C,
                /* Key */
                0x00,
                /* Initiator Logical Address */
                0x67,
                /* Transaction Identifier MS */
                0x00,
                /* Transaction Identifier LS */
                0x00,
                /* Extended Address */
                0x00,
                /* Address MS */
                0xA0,
                /* Address */
                0x00,
                /* Address */
                0x00,
                /* Address LS */
                0x00,
                /* Data Length MS */
                0x00,
                /* Data Length */
                0x00,
                /* Data Length LS */
                0x10,
                /* Header CRC */
                0x9F,
                /* Data */
                0x01,
                0x23,
                0x45,
                0x67,
                0x89,
                0xAB,
                0xCD,
                0xEF,
                0x10,
                0x11,
                0x12,
                0x13,
                0x14,
                0x15,
                0x16,
                0x17,
                /* Data CRC */
                0x56,
            },
        .header_offset = 0,
        .reply_address_length = 0,
        .reply_address_length_padded = 0,
};

const struct test_pattern test_pattern0_expected_write_reply = {
    .data =
        {/* Initiator Logical Address */
         0x67,
         /* Protocol Identifier */
         0x01,
         /* Instruction */
         0x2C,
         /* Status */
         0x00,
         /* Target Logical Address */
         0xFE,
         /* Transaction Identifier MS */
         0x00,
         /* Transaction Identifier MS */
         0x00,
         /* Header CRC */
         0xED},
    .header_offset = 0,
    .reply_address_length = 0,
    .reply_address_length_padded = 0,
};

const struct test_pattern test_pattern1_incrementing_read = {
    .data =
        {
            /* Target Logical Address */
            0xFE,
            /* Protocol Identifier */
            0x01,
            /* Instruction */
            0x4C,
            /* Key */
            0x00,
            /* Initiator Logical Address */
            0x67,
            /* Transaction Identifier MS */
            0x00,
            /* Transaction Identifier LS */
            0x01,
            /* Extended Address */
            0x00,
            /* Address MS */
            0xA0,
            /* Address */
            0x00,
            /* Address */
            0x00,
            /* Address LS */
            0x00,
            /* Data Length MS */
            0x00,
            /* Data Length */
            0x00,
            /* Data Length LS */
            0x10,
            /* Header CRC */
            0xC9,
        },
    .header_offset = 0,
    .reply_address_length = 0,
    .reply_address_length_padded = 0,
};

const struct test_pattern test_pattern1_expected_read_reply = {
    .data =
        {
            /* Initiator Logical Address */
            0x67,
            /* Protocol Identifier */
            0x01,
            /* Instruction */
            0x0C,
            /* Status */
            0x00,
            /* Target Logical Address */
            0xFE,
            /* Transaction Identifier MS */
            0x00,
            /* Transaction Identifier LS */
            0x01,
            /* Reserved */
            0x00,
            /* Data Length MS */
            0x00,
            /* Data Length */
            0x00,
            /* Data Length LS */
            0x10,
            /* Header CRC */
            0x6D,
            /* Data */
            0x01,
            0x23,
            0x45,
            0x67,
            0x89,
            0xAB,
            0xCD,
            0xEF,
            0x10,
            0x11,
            0x12,
            0x13,
            0x14,
            0x15,
            0x16,
            0x17,
            /* Data CRC */
            0x56,
        },
    .header_offset = 0,
    .reply_address_length = 0,
    .reply_address_length_padded = 0,
};

const struct test_pattern
    test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses =
        {
            .data =
                {
                    /* Target SpaceWire Address */
                    0x11,
                    0x22,
                    0x33,
                    0x44,
                    0x55,
                    0x66,
                    0x77,
                    /* Target Logical Address */
                    0xFE,
                    /* Protocol Identifier */
                    0x01,
                    /* Instruction */
                    0x6E,
                    /* Key */
                    0x00,
                    /* Reply SpaceWire Address */
                    0x00,
                    0x99,
                    0xAA,
                    0xBB,
                    0xCC,
                    0xDD,
                    0xEE,
                    0x00,
                    /* Initiator Logical Address */
                    0x67,
                    /* Transaction Identifier MS */
                    0x00,
                    /* Transaction Identifier LS */
                    0x02,
                    /* Extended Address */
                    0x00,
                    /* Address MS */
                    0xA0,
                    /* Address */
                    0x00,
                    /* Address */
                    0x00,
                    /* Address LS */
                    0x10,
                    /* Data Length MS */
                    0x00,
                    /* Data Length */
                    0x00,
                    /* Data Length LS */
                    0x10,
                    /* Header CRC */
                    0x7F,
                    /* Data */
                    0xA0,
                    0xA1,
                    0xA2,
                    0xA3,
                    0xA4,
                    0xA5,
                    0xA6,
                    0xA7,
                    0xA8,
                    0xA9,
                    0xAA,
                    0xAB,
                    0xAC,
                    0xAD,
                    0xAE,
                    0xAF,
                    /* Data CRC */
                    0xB4,
                },
            .header_offset = 7,
            .reply_address_length = 7,
            .reply_address_length_padded = 8,
};

const struct test_pattern
    test_pattern2_expected_write_reply_with_spacewire_addresses = {
        .data =
            {
                /* Reply SpaceWire Address */
                0x99,
                0xAA,
                0xBB,
                0xCC,
                0xDD,
                0xEE,
                0x00,
                /* Initiator Logical Address */
                0x67,
                /* Protocol Identifier */
                0x01,
                /* Instruction */
                0x2E,
                /* Status */
                0x00,
                /* Target Logical Address */
                0xFE,
                /* Transaction Identifier MS */
                0x00,
                /* Transaction Identifier LS */
                0x02,
                /* Header CRC */
                0x1D,
            },
        .header_offset = 7,
        .reply_address_length = 7,
        .reply_address_length_padded = 8,
};

const struct test_pattern
    test_pattern3_incrementing_read_with_spacewire_addresses = {
        .data =
            {
                /* Target SpaceWire Address */
                0x11,
                0x22,
                0x33,
                0x44,
                /* Target Logical Address */
                0xFE,
                /* Protocol Identifier */
                0x01,
                /* Instruction */
                0x4D,
                /* Key */
                0x00,
                /* Reply SpaceWire Address */
                0x99,
                0xAA,
                0xBB,
                0xCC,
                /* Initiator Logical Address */
                0x67,
                /* Transaction Identifier MS */
                0x00,
                /* Transaction Identifier LS */
                0x03,
                /* Extended Address */
                0x00,
                /* Address MS */
                0xA0,
                /* Address */
                0x00,
                /* Address */
                0x00,
                /* Address LS */
                0x10,
                /* Data Length MS */
                0x00,
                /* Data Length */
                0x00,
                /* Data Length LS */
                0x10,
                /* Header CRC */
                0xF7,
            },
        .header_offset = 4,
        .reply_address_length = 4,
        .reply_address_length_padded = 4,
};

const struct test_pattern
    test_pattern3_expected_read_reply_with_spacewire_addresses = {
        .data =
            {
                /* Reply SpaceWire Address */
                0x99,
                0xAA,
                0xBB,
                0xCC,
                /* Initiator Logical Address */
                0x67,
                /* Protocol Identifier */
                0x01,
                /* Instruction */
                0x0D,
                /* Status */
                0x00,
                /* Target Logical Address */
                0xFE,
                /* Transaction Identifier MS */
                0x00,
                /* Transaction Identifier LS */
                0x03,
                /* Reserved */
                0x00,
                /* Data Length MS */
                0x00,
                /* Data Length */
                0x00,
                /* Data Length LS */
                0x10,
                /* Header CRC */
                0x52,
                /* Data */
                0xA0,
                0xA1,
                0xA2,
                0xA3,
                0xA4,
                0xA5,
                0xA6,
                0xA7,
                0xA8,
                0xA9,
                0xAA,
                0xAB,
                0xAC,
                0xAD,
                0xAE,
                0xAF,
                /* Data CRC */
                0xB4,
            },
        .header_offset = 4,
        .reply_address_length = 4,
        .reply_address_length_padded = 4,
};

/* Custom test patterns for read-modify-write. */

const struct test_pattern test_pattern4_rmw = {
    .data =
        {
            /* Target Logical Address */
            0xFE,
            /* Protocol Identifier */
            0x01,
            /* Instruction */
            0x5C,
            /* Key */
            0x00,
            /* Initiator Logical Address */
            0x67,
            /* Transaction Identifier MS */
            0x00,
            /* Transaction Identifier LS */
            0x04,
            /* Extended Address */
            0x00,
            /* Address MS */
            0xA0,
            /* Address */
            0x00,
            /* Address */
            0x00,
            /* Address LS */
            0x10,
            /* Data Length MS */
            0x00,
            /* Data Length */
            0x00,
            /* Data Length LS */
            0x06,
            /* Header CRC */
            0x9D,
            /* Data */
            0xC0,
            0x18,
            0x02,
            /* Mask */
            0xF0,
            0x3C,
            0x03,
            /* Data CRC */
            0xE3,
        },
    .header_offset = 0,
    .reply_address_length = 0,
    .reply_address_length_padded = 0,
};

const struct test_pattern test_pattern4_expected_rmw_reply = {
    .data =
        {
            /* Initiator Logical Address */
            0x67,
            /* Protocol Identifier */
            0x01,
            /* Instruction */
            0x1C,
            /* Status */
            0x00,
            /* Target Logical Address */
            0xFE,
            /* Transaction Identifier MS */
            0x00,
            /* Transaction Identifier LS */
            0x04,
            /* Reserved */
            0x00,
            /* Data Length MS */
            0x00,
            /* Data Length */
            0x00,
            /* Data Length LS */
            0x03,
            /* Header CRC */
            0x4F,
            /* Data */
            0xA0,
            0xA1,
            0xA2,
            /* Data CRC */
            0xD7,
        },
    .header_offset = 0,
    .reply_address_length = 0,
    .reply_address_length_padded = 0,
};

const struct test_pattern test_pattern5_rmw_with_spacewire_addresses = {
    .data =
        {
            /* Target SpaceWire Address */
            0x11,
            /* Target Logical Address */
            0xFE,
            /* Protocol Identifier */
            0x01,
            /* Instruction */
            0x5D,
            /* Key */
            0x00,
            /* Reply SpaceWire Address */
            0x00,
            0x00,
            0x00,
            0x88,
            /* Initiator Logical Address */
            0x67,
            /* Transaction Identifier MS */
            0x00,
            /* Transaction Identifier LS */
            0x05,
            /* Extended Address */
            0x00,
            /* Address MS */
            0xA0,
            /* Address */
            0x00,
            /* Address */
            0x00,
            /* Address LS */
            0x10,
            /* Data Length MS */
            0x00,
            /* Data Length */
            0x00,
            /* Data Length LS */
            0x08,
            /* Header CRC */
            0xC6,
            /* Data */
            0x07,
            0x02,
            0xA0,
            0x00,
            /* Mask */
            0x0F,
            0x83,
            0xE0,
            0xFF,
            /* Data CRC */
            0x1D,
        },
    .header_offset = 1,
    .reply_address_length = 1,
    .reply_address_length_padded = 4,
};

const struct test_pattern
    test_pattern5_expected_rmw_reply_with_spacewire_addresses = {
        .data =
            {
                /* Reply SpaceWire Address */
                0x88,
                /* Initiator Logical Address */
                0x67,
                /* Protocol Identifier */
                0x01,
                /* Instruction */
                0x1D,
                /* Status */
                0x00,
                /* Target Logical Address */
                0xFE,
                /* Transaction Identifier MS */
                0x00,
                /* Transaction Identifier LS */
                0x05,
                /* Reserved */
                0x00,
                /* Data Length MS */
                0x00,
                /* Data Length */
                0x00,
                /* Data Length LS */
                0x04,
                /* Header CRC */
                0xFF,
                /* Data */
                0xE0,
                0x99,
                0xA2,
                0xA3,
                /* Data CRC */
                0x7D,
            },
        .header_offset = 1,
        .reply_address_length = 1,
        .reply_address_length_padded = 4,
};

const std::vector<struct test_pattern> test_patterns = {
    test_pattern0_unverified_incrementing_write_with_reply,
    test_pattern0_expected_write_reply,
    test_pattern1_incrementing_read,
    test_pattern1_expected_read_reply,
    test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses,
    test_pattern2_expected_write_reply_with_spacewire_addresses,
    test_pattern3_incrementing_read_with_spacewire_addresses,
    test_pattern3_expected_read_reply_with_spacewire_addresses,
    test_pattern4_rmw,
    test_pattern4_expected_rmw_reply,
    test_pattern5_rmw_with_spacewire_addresses,
    test_pattern5_expected_rmw_reply_with_spacewire_addresses,
};

const std::vector<struct test_pattern> test_patterns_commands = {
    test_pattern0_unverified_incrementing_write_with_reply,
    test_pattern1_incrementing_read,
    test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses,
    test_pattern3_incrementing_read_with_spacewire_addresses,
    test_pattern4_rmw,
    test_pattern5_rmw_with_spacewire_addresses,
};

const std::vector<struct test_pattern> test_patterns_replies = {
    test_pattern0_expected_write_reply,
    test_pattern1_expected_read_reply,
    test_pattern2_expected_write_reply_with_spacewire_addresses,
    test_pattern3_expected_read_reply_with_spacewire_addresses,
    test_pattern4_expected_rmw_reply,
    test_pattern5_expected_rmw_reply_with_spacewire_addresses,
};

const std::vector<struct test_pattern> test_patterns_with_data = {
    test_pattern0_unverified_incrementing_write_with_reply,
    test_pattern1_expected_read_reply,
    test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses,
    test_pattern3_expected_read_reply_with_spacewire_addresses,
    test_pattern4_rmw,
    test_pattern4_expected_rmw_reply,
    test_pattern5_rmw_with_spacewire_addresses,
    test_pattern5_expected_rmw_reply_with_spacewire_addresses,
};

const std::vector<struct test_pattern> test_patterns_without_data = {
    test_pattern0_expected_write_reply,
    test_pattern1_incrementing_read,
    test_pattern2_expected_write_reply_with_spacewire_addresses,
    test_pattern3_incrementing_read_with_spacewire_addresses,
};

const std::vector<std::pair<struct test_pattern, struct test_pattern>>
    test_patterns_command_reply_pairs = {
        {
            test_pattern0_unverified_incrementing_write_with_reply,
            test_pattern0_expected_write_reply,
        },
        {
            test_pattern1_incrementing_read,
            test_pattern1_expected_read_reply,
        },
        {
            test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses,
            test_pattern2_expected_write_reply_with_spacewire_addresses,
        },
        {
            test_pattern3_incrementing_read_with_spacewire_addresses,
            test_pattern3_expected_read_reply_with_spacewire_addresses,
        },
        {
            test_pattern4_rmw,
            test_pattern4_expected_rmw_reply,
        },
        {
            test_pattern5_rmw_with_spacewire_addresses,
            test_pattern5_expected_rmw_reply_with_spacewire_addresses,
        },
};
