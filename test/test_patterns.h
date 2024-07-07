#ifndef TEST_PATTERNS_H
#define TEST_PATTERNS_H

#include <cstddef>
#include <cstdint>
#include <vector>

#include "rmap.h"

struct test_pattern {
    /** Return a copy of the data field without the data CRC.
     *
     * Will return an empty container if the data field is of size 0 or if the
     * pattern packet type does not contain a data field.
     *
     * @return Copy of data field.
     */
    std::vector<uint8_t> data_field() const
    {
        const size_t data_field_offset = header_offset +
            rmap_calculate_header_size(data.data() + header_offset);
        if (data_field_offset == data.size()) {
            /* Contains no data field. */
            return {};
        }
        return std::vector<uint8_t>(
            data.begin() + data_field_offset,
            data.end() - 1);
    }

    /** Return a copy of the pattern with the spacewire address prefix removed.
     *
     * This corresponds to the packet as it would arrive at its destination
     * after each destination address except the last (target logical address)
     * have been removed by routers.
     *
     * For commands, the target spacewire addresses will be removed.
     *
     * For replies, the reply spacewire addresses will be removed.
     *
     * @return Copy of pattern without spacewire address prefix.
     */
    std::vector<uint8_t> packet_without_spacewire_address_prefix() const
    {
        return std::vector<uint8_t>(data.begin() + header_offset, data.end());
    }

    std::vector<std::uint8_t> data;
    std::size_t header_offset;
    std::size_t reply_address_length;
    std::size_t reply_address_length_padded;
};

/* RMAP test patterns from ECSS‐E‐ST‐50‐52C, 5 February 2010. */
extern const struct test_pattern
    test_pattern0_unverified_incrementing_write_with_reply;
extern const struct test_pattern test_pattern0_expected_write_reply;
extern const struct test_pattern test_pattern1_incrementing_read;
extern const struct test_pattern test_pattern1_expected_read_reply;
extern const struct test_pattern
    test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses;
extern const struct test_pattern
    test_pattern2_expected_write_reply_with_spacewire_addresses;
extern const struct test_pattern
    test_pattern3_incrementing_read_with_spacewire_addresses;
extern const struct test_pattern
    test_pattern3_expected_read_reply_with_spacewire_addresses;

/* Custom test patterns for read-modify-write. */
extern const struct test_pattern test_pattern4_rmw;
extern const struct test_pattern test_pattern4_expected_rmw_reply;
extern const struct test_pattern test_pattern5_rmw_with_spacewire_addresses;
extern const struct test_pattern
    test_pattern5_expected_rmw_reply_with_spacewire_addresses;

extern const std::vector<struct test_pattern> test_patterns;
extern const std::vector<struct test_pattern> test_patterns_commands;
extern const std::vector<struct test_pattern> test_patterns_replies;
extern const std::vector<struct test_pattern> test_patterns_with_data;
extern const std::vector<struct test_pattern> test_patterns_without_data;
extern const std::vector<std::pair<struct test_pattern, struct test_pattern>>
    test_patterns_command_reply_pairs;

#endif /* TEST_PATTERNS_H */
