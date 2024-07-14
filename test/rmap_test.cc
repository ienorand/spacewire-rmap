#include <numeric>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "rmap.h"

#include "test_patterns.h"

typedef std::tuple<uint8_t (*)(const void *), uint8_t>
    AccessorByteCheckParameters;
typedef std::tuple<struct test_pattern, AccessorByteCheckParameters>
    PatternAccessorByteCheckParameters;

class AccessorByteCheckInPattern :
    public testing::TestWithParam<PatternAccessorByteCheckParameters>
{
};

TEST_P(AccessorByteCheckInPattern, Check)
{
    const auto pattern = std::get<0>(GetParam());
    auto accessor = std::get<0>(std::get<1>(GetParam()));
    auto expected = std::get<1>(std::get<1>(GetParam()));

    EXPECT_EQ(accessor(pattern.data.data() + pattern.header_offset), expected);
}

INSTANTIATE_TEST_SUITE_P(
    TestPattern0AccessorByteChecks,
    AccessorByteCheckInPattern,
    testing::Combine(
        testing::Values(test_pattern0_unverified_incrementing_write_with_reply),
        testing::Values(
            std::make_tuple(rmap_get_protocol, 1),
            std::make_tuple(
                rmap_get_instruction,
                RMAP_PACKET_TYPE_COMMAND << RMAP_INSTRUCTION_PACKET_TYPE_SHIFT |
                    RMAP_COMMAND_CODE_INCREMENT
                        << RMAP_INSTRUCTION_COMMAND_CODE_SHIFT |
                    RMAP_COMMAND_CODE_WRITE
                        << RMAP_INSTRUCTION_COMMAND_CODE_SHIFT |
                    RMAP_COMMAND_CODE_REPLY
                        << RMAP_INSTRUCTION_COMMAND_CODE_SHIFT),
            std::make_tuple(rmap_get_key, 0),
            std::make_tuple(rmap_get_target_logical_address, 0xFE),
            std::make_tuple(rmap_get_initiator_logical_address, 0x67),
            std::make_tuple(rmap_get_extended_address, 0x00))));

INSTANTIATE_TEST_SUITE_P(
    TestPattern0ReplyAccessorByteChecks,
    AccessorByteCheckInPattern,
    testing::Combine(
        testing::Values(test_pattern0_expected_write_reply),
        testing::Values(
            std::make_tuple(rmap_get_protocol, 1),
            std::make_tuple(
                rmap_get_instruction,
                RMAP_PACKET_TYPE_REPLY << RMAP_INSTRUCTION_PACKET_TYPE_SHIFT |
                    RMAP_COMMAND_CODE_INCREMENT
                        << RMAP_INSTRUCTION_COMMAND_CODE_SHIFT |
                    RMAP_COMMAND_CODE_WRITE
                        << RMAP_INSTRUCTION_COMMAND_CODE_SHIFT |
                    RMAP_COMMAND_CODE_REPLY
                        << RMAP_INSTRUCTION_COMMAND_CODE_SHIFT),
            std::make_tuple(rmap_get_status, RMAP_STATUS_FIELD_CODE_SUCCESS),
            std::make_tuple(rmap_get_target_logical_address, 0xFE),
            std::make_tuple(rmap_get_initiator_logical_address, 0x67))));

INSTANTIATE_TEST_SUITE_P(
    TestPattern1AccessorByteChecks,
    AccessorByteCheckInPattern,
    testing::Combine(
        testing::Values(test_pattern1_incrementing_read),
        testing::Values(
            std::make_tuple(rmap_get_protocol, 1),
            std::make_tuple(
                rmap_get_instruction,
                RMAP_PACKET_TYPE_COMMAND << RMAP_INSTRUCTION_PACKET_TYPE_SHIFT |
                    RMAP_COMMAND_CODE_INCREMENT
                        << RMAP_INSTRUCTION_COMMAND_CODE_SHIFT |
                    RMAP_COMMAND_CODE_REPLY
                        << RMAP_INSTRUCTION_COMMAND_CODE_SHIFT),
            std::make_tuple(rmap_get_key, 0),
            std::make_tuple(rmap_get_target_logical_address, 0xFE),
            std::make_tuple(rmap_get_initiator_logical_address, 0x67),
            std::make_tuple(rmap_get_extended_address, 0x00))));

INSTANTIATE_TEST_SUITE_P(
    TestPattern1ReplyAccessorByteChecks,
    AccessorByteCheckInPattern,
    testing::Combine(
        testing::Values(test_pattern1_expected_read_reply),
        testing::Values(
            std::make_tuple(rmap_get_protocol, 1),
            std::make_tuple(
                rmap_get_instruction,
                RMAP_PACKET_TYPE_REPLY << RMAP_INSTRUCTION_PACKET_TYPE_SHIFT |
                    RMAP_COMMAND_CODE_INCREMENT
                        << RMAP_INSTRUCTION_COMMAND_CODE_SHIFT |
                    RMAP_COMMAND_CODE_REPLY
                        << RMAP_INSTRUCTION_COMMAND_CODE_SHIFT),
            std::make_tuple(rmap_get_status, RMAP_STATUS_FIELD_CODE_SUCCESS),
            std::make_tuple(rmap_get_target_logical_address, 0xFE),
            std::make_tuple(rmap_get_initiator_logical_address, 0x67))));

INSTANTIATE_TEST_SUITE_P(
    TestPattern2AccessorByteChecks,
    AccessorByteCheckInPattern,
    testing::Combine(
        testing::Values(
            test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses),
        testing::Values(
            std::make_tuple(rmap_get_protocol, 1),
            std::make_tuple(
                rmap_get_instruction,
                RMAP_PACKET_TYPE_COMMAND << RMAP_INSTRUCTION_PACKET_TYPE_SHIFT |
                    RMAP_COMMAND_CODE_INCREMENT
                        << RMAP_INSTRUCTION_COMMAND_CODE_SHIFT |
                    RMAP_COMMAND_CODE_WRITE
                        << RMAP_INSTRUCTION_COMMAND_CODE_SHIFT |
                    RMAP_COMMAND_CODE_REPLY
                        << RMAP_INSTRUCTION_COMMAND_CODE_SHIFT |
                    (test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses
                         .reply_address_length_padded /
                     4) << RMAP_INSTRUCTION_REPLY_ADDRESS_LENGTH_SHIFT),
            std::make_tuple(rmap_get_key, 0),
            std::make_tuple(rmap_get_target_logical_address, 0xFE),
            std::make_tuple(rmap_get_initiator_logical_address, 0x67),
            std::make_tuple(rmap_get_extended_address, 0x00))));

INSTANTIATE_TEST_SUITE_P(
    TestPattern2ReplyAccessorByteChecks,
    AccessorByteCheckInPattern,
    testing::Combine(
        testing::Values(
            test_pattern2_expected_write_reply_with_spacewire_addresses),
        testing::Values(
            std::make_tuple(rmap_get_protocol, 1),
            std::make_tuple(
                rmap_get_instruction,
                RMAP_PACKET_TYPE_REPLY << RMAP_INSTRUCTION_PACKET_TYPE_SHIFT |
                    RMAP_COMMAND_CODE_INCREMENT
                        << RMAP_INSTRUCTION_COMMAND_CODE_SHIFT |
                    RMAP_COMMAND_CODE_WRITE
                        << RMAP_INSTRUCTION_COMMAND_CODE_SHIFT |
                    RMAP_COMMAND_CODE_REPLY
                        << RMAP_INSTRUCTION_COMMAND_CODE_SHIFT |
                    (test_pattern2_expected_write_reply_with_spacewire_addresses
                         .reply_address_length_padded /
                     4) << RMAP_INSTRUCTION_REPLY_ADDRESS_LENGTH_SHIFT),
            std::make_tuple(rmap_get_status, RMAP_STATUS_FIELD_CODE_SUCCESS),
            std::make_tuple(rmap_get_target_logical_address, 0xFE),
            std::make_tuple(rmap_get_initiator_logical_address, 0x67))));

INSTANTIATE_TEST_SUITE_P(
    TestPattern3AccessorByteChecks,
    AccessorByteCheckInPattern,
    testing::Combine(
        testing::Values(
            test_pattern3_incrementing_read_with_spacewire_addresses),
        testing::Values(
            std::make_tuple(rmap_get_protocol, 1),
            std::make_tuple(
                rmap_get_instruction,
                RMAP_PACKET_TYPE_COMMAND << RMAP_INSTRUCTION_PACKET_TYPE_SHIFT |
                    RMAP_COMMAND_CODE_INCREMENT
                        << RMAP_INSTRUCTION_COMMAND_CODE_SHIFT |
                    RMAP_COMMAND_CODE_REPLY
                        << RMAP_INSTRUCTION_COMMAND_CODE_SHIFT |
                    (test_pattern3_incrementing_read_with_spacewire_addresses
                         .reply_address_length_padded /
                     4) << RMAP_INSTRUCTION_REPLY_ADDRESS_LENGTH_SHIFT),
            std::make_tuple(rmap_get_key, 0),
            std::make_tuple(rmap_get_target_logical_address, 0xFE),
            std::make_tuple(rmap_get_initiator_logical_address, 0x67),
            std::make_tuple(rmap_get_extended_address, 0x00))));

INSTANTIATE_TEST_SUITE_P(
    TestPattern3ReplyAccessorByteChecks,
    AccessorByteCheckInPattern,
    testing::Combine(
        testing::Values(
            test_pattern3_expected_read_reply_with_spacewire_addresses),
        testing::Values(
            std::make_tuple(rmap_get_protocol, 1),
            std::make_tuple(
                rmap_get_instruction,
                RMAP_PACKET_TYPE_REPLY << RMAP_INSTRUCTION_PACKET_TYPE_SHIFT |
                    RMAP_COMMAND_CODE_INCREMENT
                        << RMAP_INSTRUCTION_COMMAND_CODE_SHIFT |
                    RMAP_COMMAND_CODE_REPLY
                        << RMAP_INSTRUCTION_COMMAND_CODE_SHIFT |
                    (test_pattern3_expected_read_reply_with_spacewire_addresses
                         .reply_address_length_padded /
                     4) << RMAP_INSTRUCTION_REPLY_ADDRESS_LENGTH_SHIFT),
            std::make_tuple(rmap_get_status, RMAP_STATUS_FIELD_CODE_SUCCESS),
            std::make_tuple(rmap_get_target_logical_address, 0xFE),
            std::make_tuple(rmap_get_initiator_logical_address, 0x67))));

INSTANTIATE_TEST_SUITE_P(
    TestPattern4AccessorByteChecks,
    AccessorByteCheckInPattern,
    testing::Combine(
        testing::Values(test_pattern4_rmw),
        testing::Values(
            std::make_tuple(rmap_get_protocol, 1),
            std::make_tuple(
                rmap_get_instruction,
                RMAP_PACKET_TYPE_COMMAND << RMAP_INSTRUCTION_PACKET_TYPE_SHIFT |
                    RMAP_COMMAND_CODE_RMW
                        << RMAP_INSTRUCTION_COMMAND_CODE_SHIFT),
            std::make_tuple(rmap_get_key, 0),
            std::make_tuple(rmap_get_target_logical_address, 0xFE),
            std::make_tuple(rmap_get_initiator_logical_address, 0x67),
            std::make_tuple(rmap_get_extended_address, 0x00))));

INSTANTIATE_TEST_SUITE_P(
    TestPattern4ReplyAccessorByteChecks,
    AccessorByteCheckInPattern,
    testing::Combine(
        testing::Values(test_pattern4_expected_rmw_reply),
        testing::Values(
            std::make_tuple(rmap_get_protocol, 1),
            std::make_tuple(
                rmap_get_instruction,
                RMAP_PACKET_TYPE_REPLY << RMAP_INSTRUCTION_PACKET_TYPE_SHIFT |
                    RMAP_COMMAND_CODE_RMW
                        << RMAP_INSTRUCTION_COMMAND_CODE_SHIFT),
            std::make_tuple(rmap_get_status, RMAP_STATUS_FIELD_CODE_SUCCESS),
            std::make_tuple(rmap_get_target_logical_address, 0xFE),
            std::make_tuple(rmap_get_initiator_logical_address, 0x67))));

INSTANTIATE_TEST_SUITE_P(
    TestPattern5AccessorByteChecks,
    AccessorByteCheckInPattern,
    testing::Combine(
        testing::Values(test_pattern5_rmw_with_spacewire_addresses),
        testing::Values(
            std::make_tuple(rmap_get_protocol, 1),
            std::make_tuple(
                rmap_get_instruction,
                RMAP_PACKET_TYPE_COMMAND << RMAP_INSTRUCTION_PACKET_TYPE_SHIFT |
                    RMAP_COMMAND_CODE_RMW
                        << RMAP_INSTRUCTION_COMMAND_CODE_SHIFT |
                    (test_pattern5_rmw_with_spacewire_addresses
                         .reply_address_length_padded /
                     4) << RMAP_INSTRUCTION_REPLY_ADDRESS_LENGTH_SHIFT),
            std::make_tuple(rmap_get_key, 0),
            std::make_tuple(rmap_get_target_logical_address, 0xFE),
            std::make_tuple(rmap_get_initiator_logical_address, 0x67),
            std::make_tuple(rmap_get_extended_address, 0x00))));

INSTANTIATE_TEST_SUITE_P(
    TestPattern5ReplyAccessorByteChecks,
    AccessorByteCheckInPattern,
    testing::Combine(
        testing::Values(
            test_pattern5_expected_rmw_reply_with_spacewire_addresses),
        testing::Values(
            std::make_tuple(rmap_get_protocol, 1),
            std::make_tuple(
                rmap_get_instruction,
                RMAP_PACKET_TYPE_REPLY << RMAP_INSTRUCTION_PACKET_TYPE_SHIFT |
                    RMAP_COMMAND_CODE_RMW
                        << RMAP_INSTRUCTION_COMMAND_CODE_SHIFT |
                    (test_pattern5_expected_rmw_reply_with_spacewire_addresses
                         .reply_address_length_padded /
                     4) << RMAP_INSTRUCTION_REPLY_ADDRESS_LENGTH_SHIFT),
            std::make_tuple(rmap_get_status, RMAP_STATUS_FIELD_CODE_SUCCESS),
            std::make_tuple(rmap_get_target_logical_address, 0xFE),
            std::make_tuple(rmap_get_initiator_logical_address, 0x67))));

const std::vector<struct test_pattern> patterns_with_non_rmap_protocols = {
    {
        .data = {13, 0, 17},
        .header_offset = 0,
        .reply_address_length = 0,
        .reply_address_length_padded = 0,
    },
    {
        .data = {13, 2, 17},
        .header_offset = 0,
        .reply_address_length = 0,
        .reply_address_length_padded = 0,
    },
    {
        .data = {13, 123, 17},
        .header_offset = 0,
        .reply_address_length = 0,
        .reply_address_length_padded = 0,
    },
    {
        .data = {13, 0xFF, 17},
        .header_offset = 0,
        .reply_address_length = 0,
        .reply_address_length_padded = 0,
    },
};
INSTANTIATE_TEST_SUITE_P(
    NonRmapPatterns,
    AccessorByteCheckInPattern,
    testing::Values(
        std::make_tuple(
            patterns_with_non_rmap_protocols.at(0),
            std::make_tuple(rmap_get_protocol, 0)),
        std::make_tuple(
            patterns_with_non_rmap_protocols.at(1),
            std::make_tuple(rmap_get_protocol, 2)),
        std::make_tuple(
            patterns_with_non_rmap_protocols.at(2),
            std::make_tuple(rmap_get_protocol, 123)),
        std::make_tuple(
            patterns_with_non_rmap_protocols.at(3),
            std::make_tuple(rmap_get_protocol, 0xFF))));

TEST(SetProtocol, GetGives1AfterSet)
{
    uint8_t buf[RMAP_HEADER_MINIMUM_SIZE] = {};

    rmap_set_protocol(buf);
    EXPECT_EQ(rmap_get_protocol(buf), 1);

    memset(buf, 123, sizeof(buf));
    rmap_set_protocol(buf);
    EXPECT_EQ(rmap_get_protocol(buf), 1);
}

typedef std::tuple<
    std::tuple<enum rmap_packet_type, int, size_t>,
    std::tuple<void (*)(void *, uint8_t), uint8_t (*)(const void *)>>
    AccessorByteSetGetParameters;

class AccessorByteSetGet :
    public testing::TestWithParam<AccessorByteSetGetParameters>
{
};

TEST_P(AccessorByteSetGet, GetGivesMatchingAfterSet)
{
    uint8_t header[64];

    auto packet_type = std::get<0>(std::get<0>(GetParam()));
    auto command_code = std::get<1>(std::get<0>(GetParam()));
    auto reply_address_size = std::get<2>(std::get<0>(GetParam()));

    auto accessor_set = std::get<0>(std::get<1>(GetParam()));
    auto accessor_get = std::get<1>(std::get<1>(GetParam()));

    ASSERT_EQ(
        rmap_initialize_header(
            header,
            sizeof(header),
            packet_type,
            command_code,
            reply_address_size),
        RMAP_OK);
    accessor_set(header, 0);
    EXPECT_EQ(accessor_get(header), 0);
    accessor_set(header, 1);
    EXPECT_EQ(accessor_get(header), 1);
    accessor_set(header, 123);
    EXPECT_EQ(accessor_get(header), 123);
    accessor_set(header, 0xFF);
    EXPECT_EQ(accessor_get(header), 0xFF);
}

/* When this fixture is instantiated for instruction field accessors, it
 * verifies correct overwriting of the instruction field in an already
 * initialized header.
 *
 * For other accessors, the instantiation verifies that set and get matches
 * with different header types and reply address lengths.
 *
 * Status and key accessors do perform some invalid accesses as part of these
 * tests, since only valid for some header types, but these are expected to
 * succeed anyway.
 */

INSTANTIATE_TEST_SUITE_P(
    WriteWithoutReply,
    AccessorByteSetGet,
    testing::Combine(
        testing::Combine(
            testing::Values(RMAP_PACKET_TYPE_COMMAND),
            testing::Values(RMAP_COMMAND_CODE_WRITE),
            testing::Range(
                (size_t)0,
                (size_t)(RMAP_REPLY_ADDRESS_LENGTH_MAX + 1))),
        testing::Values(
            std::make_tuple(rmap_set_instruction, rmap_get_instruction),
            std::make_tuple(rmap_set_key, rmap_get_key),
            std::make_tuple(rmap_set_status, rmap_get_status),
            std::make_tuple(
                rmap_set_target_logical_address,
                rmap_get_target_logical_address),
            std::make_tuple(
                rmap_set_initiator_logical_address,
                rmap_get_initiator_logical_address),
            std::make_tuple(
                rmap_set_extended_address,
                rmap_get_extended_address))));

INSTANTIATE_TEST_SUITE_P(
    CommandsAndRepliesWithReply,
    AccessorByteSetGet,
    testing::Combine(
        testing::Combine(
            testing::Values(RMAP_PACKET_TYPE_COMMAND, RMAP_PACKET_TYPE_REPLY),
            testing::Values(
                RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
                RMAP_COMMAND_CODE_RMW | RMAP_COMMAND_CODE_REPLY),
            testing::Range(
                (size_t)0,
                (size_t)(RMAP_REPLY_ADDRESS_LENGTH_MAX + 1))),
        testing::Values(
            std::make_tuple(rmap_set_instruction, rmap_get_instruction),
            std::make_tuple(rmap_set_key, rmap_get_key),
            std::make_tuple(rmap_set_status, rmap_get_status),
            std::make_tuple(
                rmap_set_target_logical_address,
                rmap_get_target_logical_address),
            std::make_tuple(
                rmap_set_initiator_logical_address,
                rmap_get_initiator_logical_address),
            std::make_tuple(
                rmap_set_extended_address,
                rmap_get_extended_address))));

TEST(SetInstruction, GetGivesMatchingAfterSetValidValue)
{
    uint8_t buf[RMAP_HEADER_MINIMUM_SIZE] = {};

    const auto pattern = test_pattern0_unverified_incrementing_write_with_reply;
    const uint8_t instruction =
        rmap_get_instruction(pattern.data.data() + pattern.header_offset);

    rmap_set_instruction(buf, instruction);
    EXPECT_EQ(rmap_get_instruction(buf), instruction);
}

typedef std::tuple<bool (*)(const void *), bool> AccessorBoolCheckParameters;
typedef std::tuple<struct test_pattern, AccessorBoolCheckParameters>
    PatternAccessorBoolCheckParameters;

class AccessorBoolCheckInPattern :
    public testing::TestWithParam<PatternAccessorBoolCheckParameters>
{
};

TEST_P(AccessorBoolCheckInPattern, Check)
{
    const auto pattern = std::get<0>(GetParam());
    auto accessor = std::get<0>(std::get<1>(GetParam()));
    auto expected = std::get<1>(std::get<1>(GetParam()));

    EXPECT_EQ(accessor(pattern.data.data() + pattern.header_offset), expected);
}

INSTANTIATE_TEST_SUITE_P(
    TestPattern0AccessorBoolChecks,
    AccessorBoolCheckInPattern,
    testing::Combine(
        testing::Values(test_pattern0_unverified_incrementing_write_with_reply),
        testing::Values(
            std::make_tuple(rmap_is_command, true),
            std::make_tuple(rmap_is_unused_packet_type, false),
            std::make_tuple(rmap_is_write, true),
            std::make_tuple(rmap_is_verify_data_before_write, false),
            std::make_tuple(rmap_is_with_reply, true),
            std::make_tuple(rmap_is_increment_address, true),
            std::make_tuple(rmap_is_rmw, false),
            std::make_tuple(rmap_is_unused_command_code, false))));

INSTANTIATE_TEST_SUITE_P(
    TestPattern0ReplyAccessorBoolChecks,
    AccessorBoolCheckInPattern,
    testing::Combine(
        testing::Values(test_pattern0_expected_write_reply),
        testing::Values(
            std::make_tuple(rmap_is_command, false),
            std::make_tuple(rmap_is_unused_packet_type, false),
            std::make_tuple(rmap_is_write, true),
            std::make_tuple(rmap_is_verify_data_before_write, false),
            std::make_tuple(rmap_is_with_reply, true),
            std::make_tuple(rmap_is_increment_address, true),
            std::make_tuple(rmap_is_rmw, false),
            std::make_tuple(rmap_is_unused_command_code, false))));

INSTANTIATE_TEST_SUITE_P(
    TestPattern1AccessorBoolChecks,
    AccessorBoolCheckInPattern,
    testing::Combine(
        testing::Values(test_pattern1_incrementing_read),
        testing::Values(
            std::make_tuple(rmap_is_command, true),
            std::make_tuple(rmap_is_unused_packet_type, false),
            std::make_tuple(rmap_is_write, false),
            std::make_tuple(rmap_is_verify_data_before_write, false),
            std::make_tuple(rmap_is_with_reply, true),
            std::make_tuple(rmap_is_increment_address, true),
            std::make_tuple(rmap_is_rmw, false),
            std::make_tuple(rmap_is_unused_command_code, false))));

INSTANTIATE_TEST_SUITE_P(
    TestPattern1ReplyAccessorBoolChecks,
    AccessorBoolCheckInPattern,
    testing::Combine(
        testing::Values(test_pattern1_expected_read_reply),
        testing::Values(
            std::make_tuple(rmap_is_command, false),
            std::make_tuple(rmap_is_unused_packet_type, false),
            std::make_tuple(rmap_is_write, false),
            std::make_tuple(rmap_is_verify_data_before_write, false),
            std::make_tuple(rmap_is_with_reply, true),
            std::make_tuple(rmap_is_increment_address, true),
            std::make_tuple(rmap_is_rmw, false),
            std::make_tuple(rmap_is_unused_command_code, false))));

INSTANTIATE_TEST_SUITE_P(
    TestPattern4AccessorBoolChecks,
    AccessorBoolCheckInPattern,
    testing::Combine(
        testing::Values(test_pattern4_rmw),
        testing::Values(
            std::make_tuple(rmap_is_command, true),
            std::make_tuple(rmap_is_unused_packet_type, false),
            std::make_tuple(rmap_is_write, false),
            std::make_tuple(rmap_is_verify_data_before_write, true),
            std::make_tuple(rmap_is_with_reply, true),
            std::make_tuple(rmap_is_increment_address, true),
            std::make_tuple(rmap_is_rmw, true),
            std::make_tuple(rmap_is_unused_command_code, false))));

INSTANTIATE_TEST_SUITE_P(
    TestPattern4ReplyAccessorBoolChecks,
    AccessorBoolCheckInPattern,
    testing::Combine(
        testing::Values(test_pattern4_expected_rmw_reply),
        testing::Values(
            std::make_tuple(rmap_is_command, false),
            std::make_tuple(rmap_is_unused_packet_type, false),
            std::make_tuple(rmap_is_write, false),
            std::make_tuple(rmap_is_verify_data_before_write, true),
            std::make_tuple(rmap_is_with_reply, true),
            std::make_tuple(rmap_is_increment_address, true),
            std::make_tuple(rmap_is_rmw, true),
            std::make_tuple(rmap_is_unused_command_code, false))));

TEST(RmapIsUnusedPacketType, UnusedPacketType)
{
    uint8_t instruction;

    auto command = test_pattern0_unverified_incrementing_write_with_reply;
    uint8_t *const command_header = command.data.data() + command.header_offset;
    auto reply = test_pattern0_expected_write_reply;
    uint8_t *const reply_header = reply.data.data() + reply.header_offset;

    EXPECT_EQ(rmap_is_unused_packet_type(command_header), false);
    EXPECT_EQ(rmap_is_unused_packet_type(reply_header), false);

    instruction = rmap_get_instruction(command_header);
    rmap_set_instruction(command_header, instruction | 1 << 7);
    EXPECT_EQ(rmap_is_unused_packet_type(command_header), true);

    instruction = rmap_get_instruction(reply_header);
    rmap_set_instruction(reply_header, instruction | 1 << 7);
    EXPECT_EQ(rmap_is_unused_packet_type(reply_header), true);
}

TEST(RmapIsUnusedCommandCode, UnusedCommandCodes)
{
    auto pattern = test_pattern0_unverified_incrementing_write_with_reply;
    uint8_t *const header = pattern.data.data() + pattern.header_offset;

    EXPECT_EQ(rmap_is_unused_command_code(header), false);

    rmap_set_instruction(header, 1 << 6 | 0x0 << 2);
    EXPECT_EQ(rmap_is_unused_command_code(header), true);

    rmap_set_instruction(header, 1 << 6 | 0x1 << 2);
    EXPECT_EQ(rmap_is_unused_command_code(header), true);

    rmap_set_instruction(header, 1 << 6 | 0x4 << 2);
    EXPECT_EQ(rmap_is_unused_command_code(header), true);

    rmap_set_instruction(header, 1 << 6 | 0x5 << 2);
    EXPECT_EQ(rmap_is_unused_command_code(header), true);

    rmap_set_instruction(header, 1 << 6 | 0x6 << 2);
    EXPECT_EQ(rmap_is_unused_command_code(header), true);
}

typedef std::pair<struct test_pattern, struct test_pattern>
    CommandReplyPairParameters;

class TestPatternCommandReplyPairs :
    public testing::TestWithParam<CommandReplyPairParameters>
{
};

TEST_P(TestPatternCommandReplyPairs, RmapGetReplyAddress)
{
    uint8_t reply_address[RMAP_REPLY_ADDRESS_LENGTH_MAX];
    size_t reply_address_size;

    const auto command = std::get<0>(GetParam());
    const uint8_t *const command_header =
        command.data.data() + command.header_offset;
    const auto reply = std::get<1>(GetParam());

    EXPECT_EQ(
        rmap_get_reply_address(
            reply_address,
            &reply_address_size,
            sizeof(reply_address),
            command_header),
        RMAP_OK);
    EXPECT_EQ(reply_address_size, command.reply_address_length);
    EXPECT_EQ(
        std::vector<uint8_t>(reply_address, reply_address + reply_address_size),
        std::vector<uint8_t>(
            reply.data.data(),
            reply.data.data() + reply.header_offset));
}

INSTANTIATE_TEST_SUITE_P(
    AllCommandReplyPairs,
    TestPatternCommandReplyPairs,
    testing::ValuesIn(test_patterns_command_reply_pairs));

class TestPatternCommandReplyPairsWithNonZeroReplyAddressLength :
    public testing::TestWithParam<CommandReplyPairParameters>
{
};

TEST_P(
    TestPatternCommandReplyPairsWithNonZeroReplyAddressLength,
    RmapGetReplyAddressNotEnoughSpace)
{
    size_t reply_address_size;

    const auto command = std::get<0>(GetParam());
    const uint8_t *const command_header =
        command.data.data() + command.header_offset;
    const auto reply = std::get<1>(GetParam());
    ASSERT_GE(command.reply_address_length, 1);
    std::vector<uint8_t> reply_address(command.reply_address_length - 1);

    EXPECT_EQ(
        rmap_get_reply_address(
            reply_address.data(),
            &reply_address_size,
            reply_address.size(),
            command_header),
        RMAP_NOT_ENOUGH_SPACE);
}

INSTANTIATE_TEST_SUITE_P(
    CommandReplyPairs,
    TestPatternCommandReplyPairsWithNonZeroReplyAddressLength,
    testing::Values(
        std::make_pair(
            test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses,
            test_pattern2_expected_write_reply_with_spacewire_addresses),
        std::make_pair(
            test_pattern3_incrementing_read_with_spacewire_addresses,
            test_pattern3_expected_read_reply_with_spacewire_addresses),
        std::make_pair(
            test_pattern5_rmw_with_spacewire_addresses,
            test_pattern5_expected_rmw_reply_with_spacewire_addresses)));

typedef std::tuple<struct test_pattern, size_t>
    GetReplyAddressWithAllZeroesParameters;

class GetReplyAddressWithAllZeroes :
    public testing::TestWithParam<GetReplyAddressWithAllZeroesParameters>
{
};

TEST_P(GetReplyAddressWithAllZeroes, Check)
{
    size_t reply_address_size;
    std::vector<uint8_t> reply_address(RMAP_REPLY_ADDRESS_LENGTH_MAX);

    const auto command_pattern = std::get<0>(GetParam());
    const size_t reply_address_padded_size = std::get<1>(GetParam());
    ASSERT_THAT(reply_address_padded_size, testing::AnyOf(4, 8, 12));
    std::vector<uint8_t> command_packet =
        command_pattern.packet_without_spacewire_address_prefix();
    command_packet.erase(
        command_packet.begin() + 4,
        command_packet.begin() + 4 +
            command_pattern.reply_address_length_padded);
    const std::vector<uint8_t> zeroes_reply_address(
        reply_address_padded_size,
        0x00);
    command_packet.insert(
        command_packet.begin() + 4,
        zeroes_reply_address.begin(),
        zeroes_reply_address.end());
    const uint8_t instruction = rmap_get_instruction(command_packet.data());
    rmap_set_instruction(
        command_packet.data(),
        (instruction & ~0x3) | reply_address_padded_size / 4);
    const std::vector<uint8_t> expected_reply_address(1, 0x00);

    EXPECT_EQ(
        rmap_get_reply_address(
            reply_address.data(),
            &reply_address_size,
            reply_address.size(),
            command_packet.data()),
        RMAP_OK);

    reply_address.resize(reply_address_size);
    EXPECT_EQ(reply_address, expected_reply_address);
}

TEST_P(GetReplyAddressWithAllZeroes, NotEnoughSpace)
{
    size_t reply_address_size;
    std::vector<uint8_t> reply_address(0);

    const auto command_pattern = std::get<0>(GetParam());
    const size_t reply_address_padded_size = std::get<1>(GetParam());
    ASSERT_THAT(reply_address_padded_size, testing::AnyOf(4, 8, 12));
    std::vector<uint8_t> command_packet =
        command_pattern.packet_without_spacewire_address_prefix();
    command_packet.erase(
        command_packet.begin() + 4,
        command_packet.begin() + 4 +
            command_pattern.reply_address_length_padded);
    const std::vector<uint8_t> zeroes_reply_address(
        reply_address_padded_size,
        0x00);
    command_packet.insert(
        command_packet.begin() + 4,
        zeroes_reply_address.begin(),
        zeroes_reply_address.end());
    const uint8_t instruction = rmap_get_instruction(command_packet.data());
    rmap_set_instruction(
        command_packet.data(),
        (instruction & ~0x3) | reply_address_padded_size / 4);

    EXPECT_EQ(
        rmap_get_reply_address(
            reply_address.data(),
            &reply_address_size,
            reply_address.size(),
            command_packet.data()),
        RMAP_NOT_ENOUGH_SPACE);
}

INSTANTIATE_TEST_SUITE_P(
    Commands,
    GetReplyAddressWithAllZeroes,
    testing::Combine(
        testing::ValuesIn(test_patterns_commands),
        testing::Values(4, 8, 12)));

typedef std::tuple<std::vector<uint8_t>, std::vector<uint8_t>>
    SetReplyAddressParameters;

class SetReplyAddress : public testing::TestWithParam<SetReplyAddressParameters>
{
};

TEST_P(SetReplyAddress, SetGet)
{
    uint8_t header[64];
    uint8_t reply_address[RMAP_REPLY_ADDRESS_LENGTH_MAX];
    size_t reply_address_size;

    auto unpadded = std::get<0>(GetParam());

    ASSERT_EQ(
        rmap_initialize_header(
            header,
            sizeof(header),
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
            unpadded.size()),
        RMAP_OK);

    rmap_set_reply_address(header, unpadded.data(), unpadded.size());

    ASSERT_EQ(
        rmap_get_reply_address(
            reply_address,
            &reply_address_size,
            sizeof(reply_address),
            header),
        RMAP_OK);
    EXPECT_EQ(
        std::vector<uint8_t>(reply_address, reply_address + reply_address_size),
        unpadded);
}

TEST_P(SetReplyAddress, SetVerifyPadded)
{
    uint8_t header[64];

    auto unpadded = std::get<0>(GetParam());
    auto expected_padded = std::get<1>(GetParam());

    ASSERT_EQ(
        rmap_initialize_header(
            header,
            sizeof(header),
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
            unpadded.size()),
        RMAP_OK);

    rmap_set_reply_address(header, unpadded.data(), unpadded.size());

    ASSERT_EQ(
        std::vector<uint8_t>(header + 4, header + 4 + expected_padded.size()),
        expected_padded);
}

INSTANTIATE_TEST_SUITE_P(
    ReplyAddressPatterns,
    SetReplyAddress,
    testing::Values(
        std::make_tuple(
            std::vector<uint8_t>({0}),
            std::vector<uint8_t>({0, 0, 0, 0})),
        std::make_tuple(
            std::vector<uint8_t>({1}),
            std::vector<uint8_t>({0, 0, 0, 1})),
        std::make_tuple(
            std::vector<uint8_t>({1, 0}),
            std::vector<uint8_t>({0, 0, 1, 0})),
        std::make_tuple(
            std::vector<uint8_t>({1, 2, 3}),
            std::vector<uint8_t>({0, 1, 2, 3})),
        std::make_tuple(
            std::vector<uint8_t>({1, 0, 0, 0}),
            std::vector<uint8_t>({1, 0, 0, 0})),
        std::make_tuple(
            std::vector<uint8_t>({1, 2, 3, 4}),
            std::vector<uint8_t>({1, 2, 3, 4})),
        std::make_tuple(
            std::vector<uint8_t>({1, 2, 3, 4, 5}),
            std::vector<uint8_t>({0, 0, 0, 1, 2, 3, 4, 5})),
        std::make_tuple(
            std::vector<uint8_t>({1, 2, 3, 4, 5, 6, 7}),
            std::vector<uint8_t>({0, 1, 2, 3, 4, 5, 6, 7})),
        std::make_tuple(
            std::vector<uint8_t>({1, 2, 3, 4, 5, 6, 7, 8}),
            std::vector<uint8_t>({1, 2, 3, 4, 5, 6, 7, 8})),
        std::make_tuple(
            std::vector<uint8_t>({1, 2, 3, 4, 5, 6, 7, 8, 9}),
            std::vector<uint8_t>({0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9})),
        std::make_tuple(
            std::vector<uint8_t>({1, 2, 3, 4, 5, 6, 7, 8, 9, 0}),
            std::vector<uint8_t>({0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0})),
        std::make_tuple(
            std::vector<uint8_t>({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}),
            std::vector<uint8_t>({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11})),
        std::make_tuple(
            std::vector<uint8_t>({1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
            std::vector<uint8_t>({1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})),
        std::make_tuple(
            std::vector<uint8_t>({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}),
            std::vector<uint8_t>({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}))));

typedef std::tuple<struct test_pattern, uint16_t>
    GetTransactionIdentifierParameters;

class GetTransactionIdentifier :
    public testing::TestWithParam<GetTransactionIdentifierParameters>
{
};

TEST_P(GetTransactionIdentifier, Check)
{
    const auto pattern = std::get<0>(GetParam());
    auto expected_transaction_identifier = std::get<1>(GetParam());
    const uint8_t *const header = pattern.data.data() + pattern.header_offset;
    EXPECT_EQ(
        rmap_get_transaction_identifier(header),
        expected_transaction_identifier);
}

INSTANTIATE_TEST_SUITE_P(
    AllTestPatterns,
    GetTransactionIdentifier,
    testing::Values(
        std::make_tuple(
            test_pattern0_unverified_incrementing_write_with_reply,
            0x0000),
        std::make_tuple(test_pattern0_expected_write_reply, 0x0000),
        std::make_tuple(test_pattern1_incrementing_read, 0x0001),
        std::make_tuple(test_pattern1_expected_read_reply, 0x0001),
        std::make_tuple(
            test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses,
            0x0002),
        std::make_tuple(
            test_pattern2_expected_write_reply_with_spacewire_addresses,
            0x0002),
        std::make_tuple(
            test_pattern3_incrementing_read_with_spacewire_addresses,
            0x0003),
        std::make_tuple(
            test_pattern3_expected_read_reply_with_spacewire_addresses,
            0x0003),
        std::make_tuple(test_pattern4_rmw, 0x0004),
        std::make_tuple(test_pattern4_expected_rmw_reply, 0x0004),
        std::make_tuple(test_pattern5_rmw_with_spacewire_addresses, 0x0005),
        std::make_tuple(
            test_pattern5_expected_rmw_reply_with_spacewire_addresses,
            0x0005)));

typedef std::tuple<enum rmap_packet_type, int, size_t>
    SetTransactionIdentifierParameters;

class SetTransactionIdentifier :
    public testing::TestWithParam<SetTransactionIdentifierParameters>
{
};

TEST_P(SetTransactionIdentifier, GetGivesMatchingAfterSet)
{
    uint8_t header[64];

    auto packet_type = std::get<0>(GetParam());
    auto command_code = std::get<1>(GetParam());
    auto reply_address_size = std::get<2>(GetParam());

    ASSERT_EQ(
        rmap_initialize_header(
            header,
            sizeof(header),
            packet_type,
            command_code,
            reply_address_size),
        RMAP_OK);
    rmap_set_transaction_identifier(header, 0);
    EXPECT_EQ(rmap_get_transaction_identifier(header), 0);
    rmap_set_transaction_identifier(header, 1);
    EXPECT_EQ(rmap_get_transaction_identifier(header), 1);
    rmap_set_transaction_identifier(header, 12345);
    EXPECT_EQ(rmap_get_transaction_identifier(header), 12345);
    rmap_set_transaction_identifier(header, 0xFFFF);
    EXPECT_EQ(rmap_get_transaction_identifier(header), 0xFFFF);
}

INSTANTIATE_TEST_SUITE_P(
    WriteWithoutReply,
    SetTransactionIdentifier,
    testing::Values(
        std::make_tuple(RMAP_PACKET_TYPE_COMMAND, RMAP_COMMAND_CODE_WRITE, 0)));

INSTANTIATE_TEST_SUITE_P(
    CommandsAndRepliesWithReply,
    SetTransactionIdentifier,
    testing::Combine(
        testing::Values(RMAP_PACKET_TYPE_COMMAND, RMAP_PACKET_TYPE_REPLY),
        testing::Values(
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
            RMAP_COMMAND_CODE_RMW,
            RMAP_COMMAND_CODE_REPLY),
        testing::Range(
            (size_t)0,
            (size_t)(RMAP_REPLY_ADDRESS_LENGTH_MAX + 1))));

typedef std::tuple<struct test_pattern, uint32_t> GetAddressParameters;

class GetAddress : public testing::TestWithParam<GetAddressParameters>
{
};

TEST_P(GetAddress, Check)
{
    const auto pattern = std::get<0>(GetParam());
    auto expected_address = std::get<1>(GetParam());
    const uint8_t *const header = pattern.data.data() + pattern.header_offset;
    EXPECT_EQ(rmap_get_address(header), expected_address);
}

INSTANTIATE_TEST_SUITE_P(
    TestPatternsCommands,
    GetAddress,
    testing::Values(
        std::make_tuple(
            test_pattern0_unverified_incrementing_write_with_reply,
            0xA0000000),
        std::make_tuple(test_pattern1_incrementing_read, 0xA0000000),
        std::make_tuple(
            test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses,
            0xA0000010),
        std::make_tuple(
            test_pattern3_incrementing_read_with_spacewire_addresses,
            0xA0000010),
        std::make_tuple(test_pattern4_rmw, 0xA0000010),
        std::make_tuple(
            test_pattern5_rmw_with_spacewire_addresses,
            0xA0000010)));

typedef std::tuple<enum rmap_packet_type, int, size_t> SetAddressParameters;

class SetAddress : public testing::TestWithParam<SetAddressParameters>
{
};

TEST_P(SetAddress, GetGivesMatchingAfterSet)
{
    uint8_t header[64];

    auto packet_type = std::get<0>(GetParam());
    auto command_code = std::get<1>(GetParam());
    auto reply_address_size = std::get<2>(GetParam());

    ASSERT_EQ(
        rmap_initialize_header(
            header,
            sizeof(header),
            packet_type,
            command_code,
            reply_address_size),
        RMAP_OK);
    rmap_set_address(header, 0);
    EXPECT_EQ(rmap_get_address(header), 0);
    rmap_set_address(header, 1);
    EXPECT_EQ(rmap_get_address(header), 1);
    rmap_set_address(header, 1234567890);
    EXPECT_EQ(rmap_get_address(header), 1234567890);
    rmap_set_address(header, 0xFFFFFFFF);
    EXPECT_EQ(rmap_get_address(header), 0xFFFFFFFF);
}

INSTANTIATE_TEST_SUITE_P(
    WriteWithoutReply,
    SetAddress,
    testing::Values(
        std::make_tuple(RMAP_PACKET_TYPE_COMMAND, RMAP_COMMAND_CODE_WRITE, 0)));

INSTANTIATE_TEST_SUITE_P(
    CommandsWithReply,
    SetAddress,
    testing::Combine(
        testing::Values(RMAP_PACKET_TYPE_COMMAND),
        testing::Values(
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
            RMAP_COMMAND_CODE_RMW,
            RMAP_COMMAND_CODE_REPLY),
        testing::Range(
            (size_t)0,
            (size_t)(RMAP_REPLY_ADDRESS_LENGTH_MAX + 1))));

typedef std::tuple<struct test_pattern, uint32_t> GetDataLengthParameter;

class GetDataLength : public testing::TestWithParam<GetDataLengthParameter>
{
};

TEST_P(GetDataLength, Check)
{
    const auto pattern = std::get<0>(GetParam());
    auto expected_data_length = std::get<1>(GetParam());
    const uint8_t *const header = pattern.data.data() + pattern.header_offset;
    EXPECT_EQ(rmap_get_data_length(header), expected_data_length);
}

INSTANTIATE_TEST_SUITE_P(
    TestPatternsWithDataLength,
    GetDataLength,
    testing::Values(
        std::make_tuple(
            test_pattern0_unverified_incrementing_write_with_reply,
            0x000010),
        std::make_tuple(test_pattern0_expected_write_reply, 0),
        std::make_tuple(test_pattern1_expected_read_reply, 0x000010),
        std::make_tuple(
            test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses,
            0x000010),
        std::make_tuple(
            test_pattern2_expected_write_reply_with_spacewire_addresses,
            0),
        std::make_tuple(
            test_pattern3_expected_read_reply_with_spacewire_addresses,
            0x000010),
        std::make_tuple(test_pattern4_rmw, 0x00000006),
        std::make_tuple(test_pattern4_expected_rmw_reply, 0x00000003),
        std::make_tuple(test_pattern5_rmw_with_spacewire_addresses, 0x00000008),
        std::make_tuple(
            test_pattern5_expected_rmw_reply_with_spacewire_addresses,
            0x00000004)));

typedef std::tuple<enum rmap_packet_type, int, size_t> SetDataLengthParameters;

class SetDataLength : public testing::TestWithParam<SetDataLengthParameters>
{
};

TEST_P(SetDataLength, GetGivesMatchingAfterSet)
{
    uint8_t header[64];

    auto packet_type = std::get<0>(GetParam());
    auto command_code = std::get<1>(GetParam());
    auto reply_address_size = std::get<2>(GetParam());

    ASSERT_EQ(
        rmap_initialize_header(
            header,
            sizeof(header),
            packet_type,
            command_code,
            reply_address_size),
        RMAP_OK);
    rmap_set_data_length(header, 0);
    EXPECT_EQ(rmap_get_data_length(header), 0);
    rmap_set_data_length(header, 1);
    EXPECT_EQ(rmap_get_data_length(header), 1);
    rmap_set_data_length(header, 12345678);
    EXPECT_EQ(rmap_get_data_length(header), 12345678);
    rmap_set_data_length(header, 0xFFFFFF);
    EXPECT_EQ(rmap_get_data_length(header), 0xFFFFFF);
}

INSTANTIATE_TEST_SUITE_P(
    WriteWithoutReply,
    SetDataLength,
    testing::Values(
        std::make_tuple(RMAP_PACKET_TYPE_COMMAND, RMAP_COMMAND_CODE_WRITE, 0)));

INSTANTIATE_TEST_SUITE_P(
    WriteWithReply,
    SetDataLength,
    testing::Combine(
        testing::Values(RMAP_PACKET_TYPE_COMMAND),
        testing::Values(RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY),
        testing::Range(
            (size_t)0,
            (size_t)(RMAP_REPLY_ADDRESS_LENGTH_MAX + 1))));

INSTANTIATE_TEST_SUITE_P(
    Read,
    SetDataLength,
    testing::Combine(
        testing::Values(RMAP_PACKET_TYPE_COMMAND),
        testing::Values(RMAP_COMMAND_CODE_REPLY),
        testing::Range(
            (size_t)0,
            (size_t)(RMAP_REPLY_ADDRESS_LENGTH_MAX + 1))));

INSTANTIATE_TEST_SUITE_P(
    ReadReply,
    SetDataLength,
    testing::Combine(
        testing::Values(RMAP_PACKET_TYPE_REPLY),
        testing::Values(RMAP_COMMAND_CODE_REPLY),
        testing::Range(
            (size_t)0,
            (size_t)(RMAP_REPLY_ADDRESS_LENGTH_MAX + 1))));

INSTANTIATE_TEST_SUITE_P(
    Rmw,
    SetDataLength,
    testing::Combine(
        testing::Values(RMAP_PACKET_TYPE_COMMAND),
        testing::Values(RMAP_COMMAND_CODE_RMW),
        testing::Range(
            (size_t)0,
            (size_t)(RMAP_REPLY_ADDRESS_LENGTH_MAX + 1))));

INSTANTIATE_TEST_SUITE_P(
    RmwReply,
    SetDataLength,
    testing::Combine(
        testing::Values(RMAP_PACKET_TYPE_REPLY),
        testing::Values(RMAP_COMMAND_CODE_RMW),
        testing::Range(
            (size_t)0,
            (size_t)(RMAP_REPLY_ADDRESS_LENGTH_MAX + 1))));

TEST(SetAndGetDataLength, WriteReply)
{
    uint8_t header[64];

    const size_t reply_address_size = 0;
    ASSERT_EQ(
        rmap_initialize_header(
            header,
            sizeof(header),
            RMAP_PACKET_TYPE_REPLY,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
            reply_address_size),
        RMAP_OK);
    /* Write reply contains no data length field, expect set to succeed
     * silently and expect get to always return 0.
     */
    rmap_set_data_length(header, 0);
    EXPECT_EQ(rmap_get_data_length(header), 0);
    rmap_set_data_length(header, 1);
    EXPECT_EQ(rmap_get_data_length(header), 0);
    rmap_set_data_length(header, 12345678);
    EXPECT_EQ(rmap_get_data_length(header), 0);
    rmap_set_data_length(header, 0xFFFFFF);
    EXPECT_EQ(rmap_get_data_length(header), 0);
}

typedef std::tuple<struct test_pattern, size_t>
    TestPatternCalculateHeaderSizeParameters;

class TestPatternCalculateHeaderSize :
    public testing::TestWithParam<TestPatternCalculateHeaderSizeParameters>
{
};

TEST_P(TestPatternCalculateHeaderSize, Check)
{
    const auto pattern = std::get<0>(GetParam());
    auto expected_header_size = std::get<1>(GetParam());
    const uint8_t *const header = pattern.data.data() + pattern.header_offset;
    EXPECT_EQ(rmap_calculate_header_size(header), expected_header_size);
}

INSTANTIATE_TEST_SUITE_P(
    AllTestPatterns,
    TestPatternCalculateHeaderSize,
    testing::Values(
        std::make_tuple(
            test_pattern0_unverified_incrementing_write_with_reply,
            RMAP_COMMAND_HEADER_STATIC_SIZE +
                test_pattern0_unverified_incrementing_write_with_reply
                    .reply_address_length_padded),
        std::make_tuple(
            test_pattern0_expected_write_reply,
            RMAP_WRITE_REPLY_HEADER_STATIC_SIZE),
        std::make_tuple(
            test_pattern1_incrementing_read,
            RMAP_COMMAND_HEADER_STATIC_SIZE +
                test_pattern1_incrementing_read.reply_address_length_padded),
        std::make_tuple(
            test_pattern1_expected_read_reply,
            RMAP_READ_REPLY_HEADER_STATIC_SIZE),
        std::make_tuple(
            test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses,
            RMAP_COMMAND_HEADER_STATIC_SIZE +
                test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses
                    .reply_address_length_padded),
        std::make_tuple(
            test_pattern2_expected_write_reply_with_spacewire_addresses,
            RMAP_WRITE_REPLY_HEADER_STATIC_SIZE),
        std::make_tuple(
            test_pattern3_incrementing_read_with_spacewire_addresses,
            RMAP_COMMAND_HEADER_STATIC_SIZE +
                test_pattern3_incrementing_read_with_spacewire_addresses
                    .reply_address_length_padded),
        std::make_tuple(
            test_pattern3_expected_read_reply_with_spacewire_addresses,
            RMAP_READ_REPLY_HEADER_STATIC_SIZE),
        std::make_tuple(
            test_pattern4_rmw,
            RMAP_COMMAND_HEADER_STATIC_SIZE +
                test_pattern4_rmw.reply_address_length_padded),
        std::make_tuple(
            test_pattern4_expected_rmw_reply,
            RMAP_READ_REPLY_HEADER_STATIC_SIZE),
        std::make_tuple(
            test_pattern5_rmw_with_spacewire_addresses,
            RMAP_COMMAND_HEADER_STATIC_SIZE +
                test_pattern5_rmw_with_spacewire_addresses
                    .reply_address_length_padded),
        std::make_tuple(
            test_pattern5_expected_rmw_reply_with_spacewire_addresses,
            RMAP_READ_REPLY_HEADER_STATIC_SIZE)));

typedef std::tuple<enum rmap_packet_type, int, std::tuple<size_t, size_t>>
    CalculateHeaderSizeParameters;

class CalculateHeaderSize :
    public testing::TestWithParam<CalculateHeaderSizeParameters>
{
};

TEST_P(CalculateHeaderSize, GetGivesMatchingAfterInitalizing)
{
    uint8_t header[64];

    auto packet_type = std::get<0>(GetParam());
    auto command_code = std::get<1>(GetParam());
    auto reply_address_unpadded_size = std::get<0>(std::get<2>(GetParam()));
    auto expected = std::get<1>(std::get<2>(GetParam()));

    ASSERT_EQ(
        rmap_initialize_header(
            header,
            sizeof(header),
            packet_type,
            command_code,
            reply_address_unpadded_size),
        RMAP_OK);

    EXPECT_EQ(rmap_calculate_header_size(header), expected);
}

INSTANTIATE_TEST_SUITE_P(
    Command,
    CalculateHeaderSize,
    testing::Combine(
        testing::Values(RMAP_PACKET_TYPE_COMMAND),
        testing::Values(
            RMAP_COMMAND_CODE_WRITE,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
            RMAP_COMMAND_CODE_RMW,
            RMAP_COMMAND_CODE_REPLY),
        testing::Values(
            std::make_tuple((size_t)0, (size_t)RMAP_COMMAND_HEADER_STATIC_SIZE),
            std::make_tuple(
                (size_t)1,
                (size_t)RMAP_COMMAND_HEADER_STATIC_SIZE + 4),
            std::make_tuple(
                (size_t)2,
                (size_t)RMAP_COMMAND_HEADER_STATIC_SIZE + 4),
            std::make_tuple(
                (size_t)3,
                (size_t)RMAP_COMMAND_HEADER_STATIC_SIZE + 4),
            std::make_tuple(
                (size_t)4,
                (size_t)RMAP_COMMAND_HEADER_STATIC_SIZE + 4),
            std::make_tuple(
                (size_t)5,
                (size_t)RMAP_COMMAND_HEADER_STATIC_SIZE + 8),
            std::make_tuple(
                (size_t)6,
                (size_t)RMAP_COMMAND_HEADER_STATIC_SIZE + 8),
            std::make_tuple(
                (size_t)7,
                (size_t)RMAP_COMMAND_HEADER_STATIC_SIZE + 8),
            std::make_tuple(
                (size_t)8,
                (size_t)RMAP_COMMAND_HEADER_STATIC_SIZE + 8),
            std::make_tuple(
                (size_t)9,
                (size_t)RMAP_COMMAND_HEADER_STATIC_SIZE + 12),
            std::make_tuple(
                (size_t)10,
                (size_t)RMAP_COMMAND_HEADER_STATIC_SIZE + 12),
            std::make_tuple(
                (size_t)11,
                (size_t)RMAP_COMMAND_HEADER_STATIC_SIZE + 12),
            std::make_tuple(
                (size_t)12,
                (size_t)RMAP_COMMAND_HEADER_STATIC_SIZE + 12))));

INSTANTIATE_TEST_SUITE_P(
    WriteReply,
    CalculateHeaderSize,
    testing::Combine(
        testing::Values(RMAP_PACKET_TYPE_REPLY),
        testing::Values(RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY),
        testing::Combine(
            testing::Range(
                (size_t)0,
                (size_t)RMAP_REPLY_ADDRESS_LENGTH_MAX + 1),
            testing::Values(RMAP_WRITE_REPLY_HEADER_STATIC_SIZE))));

INSTANTIATE_TEST_SUITE_P(
    ReadReply,
    CalculateHeaderSize,
    testing::Combine(
        testing::Values(RMAP_PACKET_TYPE_REPLY),
        testing::Values(RMAP_COMMAND_CODE_REPLY),
        testing::Combine(
            testing::Range(
                (size_t)0,
                (size_t)RMAP_REPLY_ADDRESS_LENGTH_MAX + 1),
            testing::Values(RMAP_READ_REPLY_HEADER_STATIC_SIZE))));

INSTANTIATE_TEST_SUITE_P(
    RmwReply,
    CalculateHeaderSize,
    testing::Combine(
        testing::Values(RMAP_PACKET_TYPE_REPLY),
        testing::Values(RMAP_COMMAND_CODE_RMW),
        testing::Combine(
            testing::Range(
                (size_t)0,
                (size_t)RMAP_REPLY_ADDRESS_LENGTH_MAX + 1),
            testing::Values(RMAP_READ_REPLY_HEADER_STATIC_SIZE))));

class TestPatterns : public testing::TestWithParam<struct test_pattern>
{
};

TEST_P(TestPatterns, RmapCalculateAndSetHeaderCrcPatternsShouldNotChange)
{
    const auto pattern = GetParam();

    std::vector<uint8_t> packet =
        pattern.packet_without_spacewire_address_prefix();
    const auto expected_packet = packet;
    /* CRC is corrupted first, to make sure that an implementation that does
     * nothing cannot pass the test.
     */
    packet.at(rmap_calculate_header_size(packet.data()) - 1) ^= 0xFF;
    rmap_calculate_and_set_header_crc(packet.data());
    EXPECT_EQ(packet, expected_packet);
}

TEST_P(TestPatterns, VerifyHeaderIntegrityOk)
{
    const auto pattern = GetParam();

    std::vector<uint8_t> packet =
        pattern.packet_without_spacewire_address_prefix();
    EXPECT_EQ(
        rmap_verify_header_integrity(packet.data(), packet.size()),
        RMAP_OK);
}

TEST_P(TestPatterns, VerifyHeaderIntegrityNoRmapProtocol)
{
    uint8_t protocol;

    const auto pattern = GetParam();

    std::vector<uint8_t> packet =
        pattern.packet_without_spacewire_address_prefix();

    /* Set all non-RMAP protocol values. */
    protocol = 0;
    do {
        if (protocol == 1) {
            /* Valid, skip. */
            continue;
        }
        packet.at(1) = protocol;
        rmap_calculate_and_set_header_crc(packet.data());
        EXPECT_EQ(
            rmap_verify_header_integrity(packet.data(), packet.size()),
            RMAP_NO_RMAP_PROTOCOL);
    } while (++protocol);
}

TEST_P(TestPatterns, VerifyHeaderIntegrityCrcErrorFromCorruptKeyOrStatus)
{
    unsigned int i;

    const auto pattern = GetParam();

    const std::vector<uint8_t> original_packet =
        pattern.packet_without_spacewire_address_prefix();
    auto packet = original_packet;

    /* Flip one or more bits in the key field in commands or in the status field
     * in replies.
     */
    const size_t corrupt_offset = 3;
    for (i = 1; i < 0xFF; ++i) {
        packet.at(corrupt_offset) = original_packet.at(corrupt_offset) ^ i;
        EXPECT_EQ(
            rmap_verify_header_integrity(packet.data(), packet.size()),
            RMAP_HEADER_CRC_ERROR);
    }
}

TEST_P(TestPatterns, VerifyHeaderIntegrityCrcErrorFromCorruptCrcField)
{
    unsigned int i;

    const auto pattern = GetParam();

    const std::vector<uint8_t> original_packet(
        pattern.data.begin() + pattern.header_offset,
        pattern.data.end());
    auto packet = original_packet;

    /* Flip one or more bits in the CRC field. */
    const size_t corrupt_offset = rmap_calculate_header_size(packet.data()) - 1;
    for (i = 1; i < 0xFF; ++i) {
        packet.at(corrupt_offset) = original_packet.at(corrupt_offset) ^ i;
        EXPECT_EQ(
            rmap_verify_header_integrity(packet.data(), packet.size()),
            RMAP_HEADER_CRC_ERROR);
    }
}

TEST_P(TestPatterns, VerifyHeaderIntegrityIncompleteHeader)
{
    size_t incomplete_header_size;

    const auto pattern = GetParam();
    const uint8_t *const header = pattern.data.data() + pattern.header_offset;

    const enum rmap_status expected_status = RMAP_INCOMPLETE_HEADER;

    incomplete_header_size = 0;
    EXPECT_EQ(
        rmap_verify_header_integrity(header, incomplete_header_size),
        expected_status);

    incomplete_header_size = 1;
    EXPECT_EQ(
        rmap_verify_header_integrity(header, incomplete_header_size),
        expected_status);

    incomplete_header_size = RMAP_HEADER_MINIMUM_SIZE - 1;
    EXPECT_EQ(
        rmap_verify_header_integrity(header, incomplete_header_size),
        expected_status);

    incomplete_header_size = rmap_calculate_header_size(header) - 1;
    EXPECT_EQ(
        rmap_verify_header_integrity(header, incomplete_header_size),
        expected_status);
}

TEST_P(TestPatterns, VerifyHeaderIntegrityCompleteHeaderOnly)
{
    const auto pattern = GetParam();
    const uint8_t *const header = pattern.data.data() + pattern.header_offset;

    EXPECT_EQ(
        rmap_verify_header_integrity(
            header,
            rmap_calculate_header_size(header)),
        RMAP_OK);
}

TEST_P(TestPatterns, VerifyHeaderInstructionOk)
{
    const auto pattern = GetParam();
    const uint8_t *const header = pattern.data.data() + pattern.header_offset;

    EXPECT_EQ(rmap_verify_header_instruction(header), RMAP_OK);
}

TEST_P(TestPatterns, RmapInitializeHeaderPatternsShouldNotChange)
{
    enum rmap_packet_type packet_type;
    int command_code;
    size_t header_offset;

    const auto pattern = GetParam();

    std::vector<uint8_t> packet =
        pattern.packet_without_spacewire_address_prefix();

    packet_type = RMAP_PACKET_TYPE_COMMAND;
    if (!rmap_is_command(packet.data())) {
        packet_type = RMAP_PACKET_TYPE_REPLY;
    }

    command_code = 0;
    if (rmap_is_write(packet.data())) {
        command_code |= RMAP_COMMAND_CODE_WRITE;
    }
    if (rmap_is_verify_data_before_write(packet.data())) {
        command_code |= RMAP_COMMAND_CODE_VERIFY;
    }
    if (rmap_is_with_reply(packet.data())) {
        command_code |= RMAP_COMMAND_CODE_REPLY;
    }
    if (rmap_is_increment_address(packet.data())) {
        command_code |= RMAP_COMMAND_CODE_INCREMENT;
    }

    const auto expected_packet = packet;
    /* Protocol identifier and instruction is corrupted first, to make sure that
     * an implementation that does nothing cannot pass the test.
     */
    packet.at(1) ^= 0xFF;
    packet.at(2) ^= 0xFF;
    const auto corrupted_packet = packet;

    EXPECT_EQ(
        rmap_initialize_header(
            packet.data(),
            packet.size(),
            packet_type,
            command_code,
            pattern.reply_address_length),
        RMAP_OK);
    EXPECT_EQ(packet, expected_packet);

    packet = corrupted_packet;

    /* Also verified for patterns which do not contain any data field. Should
     * work correctly regardless.
     */
    EXPECT_EQ(
        rmap_initialize_header_before(
            &header_offset,
            packet.data(),
            rmap_calculate_header_size(expected_packet.data()),
            packet_type,
            command_code,
            pattern.reply_address_length),
        RMAP_OK);
    EXPECT_EQ(packet, expected_packet);
    EXPECT_EQ(header_offset, 0);
}

INSTANTIATE_TEST_SUITE_P(
    AllTestPatterns,
    TestPatterns,
    testing::ValuesIn(test_patterns));

class TestPatternsWithData : public testing::TestWithParam<struct test_pattern>
{
};

TEST_P(TestPatternsWithData, VerifyDataCrcErrorFromCorruptData)
{
    unsigned int i;

    const auto pattern = GetParam();

    const std::vector<uint8_t> original_packet =
        pattern.packet_without_spacewire_address_prefix();
    auto packet = original_packet;

    /* Flip one or more bits in the data byte immediately following the header.
     */
    const size_t corrupt_offset = rmap_calculate_header_size(packet.data());
    for (i = 1; i < 0xFF; ++i) {
        packet.at(corrupt_offset) = original_packet.at(corrupt_offset) ^ i;
        EXPECT_EQ(
            rmap_verify_data(packet.data(), packet.size()),
            RMAP_INVALID_DATA_CRC);
    }
}

TEST_P(TestPatternsWithData, VerifyDataCrcErrorFromCorruptCrcField)
{
    unsigned int i;

    const auto pattern = GetParam();

    const std::vector<uint8_t> original_packet =
        pattern.packet_without_spacewire_address_prefix();
    auto packet = original_packet;

    /* Flip one or more bits in the CRC field. */
    const size_t corrupt_offset = rmap_calculate_header_size(packet.data()) +
        rmap_get_data_length(packet.data());
    for (i = 1; i < 0xFF; ++i) {
        packet.at(corrupt_offset) = original_packet.at(corrupt_offset) ^ i;
        EXPECT_EQ(
            rmap_verify_data(packet.data(), packet.size()),
            RMAP_INVALID_DATA_CRC);
    }
}

TEST_P(TestPatternsWithData, VerifyDataIncompleteData)
{
    size_t incomplete_packet_size;

    const auto pattern = GetParam();

    const std::vector<uint8_t> packet =
        pattern.packet_without_spacewire_address_prefix();

    const enum rmap_status expected_status = RMAP_INSUFFICIENT_DATA;

    incomplete_packet_size = rmap_calculate_header_size(packet.data());
    EXPECT_EQ(
        rmap_verify_data(packet.data(), incomplete_packet_size),
        expected_status);

    incomplete_packet_size = rmap_calculate_header_size(packet.data()) + 1;
    EXPECT_EQ(
        rmap_verify_data(packet.data(), incomplete_packet_size),
        expected_status);

    incomplete_packet_size = packet.size() - 2;
    EXPECT_EQ(
        rmap_verify_data(packet.data(), incomplete_packet_size),
        expected_status);

    incomplete_packet_size = packet.size() - 1;
    EXPECT_EQ(
        rmap_verify_data(packet.data(), incomplete_packet_size),
        expected_status);
}

TEST_P(TestPatternsWithData, VerifyDataTooMuchData)
{
    size_t too_long_packet_size;

    const auto pattern = GetParam();

    const std::vector<uint8_t> original_packet =
        pattern.packet_without_spacewire_address_prefix();
    auto packet = original_packet;

    packet.resize(RMAP_HEADER_SIZE_MAX + RMAP_DATA_LENGTH_MAX + 1);

    const enum rmap_status expected_status = RMAP_TOO_MUCH_DATA;

    too_long_packet_size = original_packet.size() + 1;
    EXPECT_EQ(
        rmap_verify_data(packet.data(), too_long_packet_size),
        expected_status);

    too_long_packet_size = original_packet.size() + 123;
    EXPECT_EQ(
        rmap_verify_data(packet.data(), too_long_packet_size),
        expected_status);

    too_long_packet_size = RMAP_HEADER_SIZE_MAX + RMAP_DATA_LENGTH_MAX - 1;
    EXPECT_EQ(
        rmap_verify_data(packet.data(), too_long_packet_size),
        expected_status);

    too_long_packet_size = RMAP_HEADER_SIZE_MAX + RMAP_DATA_LENGTH_MAX;
    EXPECT_EQ(
        rmap_verify_data(packet.data(), too_long_packet_size),
        expected_status);

    too_long_packet_size = RMAP_HEADER_SIZE_MAX + RMAP_DATA_LENGTH_MAX + 1;
    EXPECT_EQ(
        rmap_verify_data(packet.data(), too_long_packet_size),
        expected_status);
}

TEST_P(TestPatternsWithData, VerifyDataOk)
{
    const auto pattern = GetParam();

    const std::vector<uint8_t> packet =
        pattern.packet_without_spacewire_address_prefix();

    EXPECT_EQ(rmap_verify_data(packet.data(), packet.size()), RMAP_OK);
}

INSTANTIATE_TEST_SUITE_P(
    PatternsWithData,
    TestPatternsWithData,
    testing::ValuesIn(test_patterns_with_data));

typedef std::tuple<struct test_pattern, size_t>
    VerifyDataRmwDataLengthErrorParameters;

class VerifyDataRmwDataLengthError :
    public testing::TestWithParam<VerifyDataRmwDataLengthErrorParameters>
{
};

TEST_P(VerifyDataRmwDataLengthError, Check)
{
    const auto pattern = std::get<0>(GetParam());
    const size_t data_size = std::get<1>(GetParam());

    std::vector<uint8_t> packet =
        pattern.packet_without_spacewire_address_prefix();
    rmap_set_data_length(packet.data(), data_size);
    rmap_calculate_and_set_header_crc(packet.data());
    packet.resize(rmap_calculate_header_size(packet.data()));
    std::vector<uint8_t> data = pattern.data_field();
    data.resize(data_size, 0xDA);
    packet.insert(packet.end(), data.begin(), data.end());
    packet.back() = rmap_crc_calculate(data.data(), data.size());

    EXPECT_EQ(
        rmap_verify_data(packet.data(), packet.size()),
        RMAP_RMW_DATA_LENGTH_ERROR);
}

INSTANTIATE_TEST_SUITE_P(
    RmwCommands,
    VerifyDataRmwDataLengthError,
    testing::Combine(
        testing::Values(
            test_pattern4_rmw,
            test_pattern5_rmw_with_spacewire_addresses),
        testing::Values(1, 3, 5, 7, 9, 123)));

INSTANTIATE_TEST_SUITE_P(
    RmwReplies,
    VerifyDataRmwDataLengthError,
    testing::Combine(
        testing::Values(
            test_pattern4_expected_rmw_reply,
            test_pattern5_expected_rmw_reply_with_spacewire_addresses),
        testing::Values(5, 123)));

class TestPatternsWithoutData :
    public testing::TestWithParam<struct test_pattern>
{
};

TEST_P(TestPatternsWithoutData, VerifyDataNoData)
{
    const auto pattern = GetParam();

    const std::vector<uint8_t> packet =
        pattern.packet_without_spacewire_address_prefix();

    EXPECT_EQ(rmap_verify_data(packet.data(), packet.size()), RMAP_NO_DATA);
}

INSTANTIATE_TEST_SUITE_P(
    PatternsWithoutData,
    TestPatternsWithoutData,
    testing::ValuesIn(test_patterns_without_data));

typedef std::tuple<enum rmap_packet_type, int, size_t, enum rmap_status>
    VerifyHeaderInstructionParameters;

class VerifyHeaderInstruction :
    public testing::TestWithParam<VerifyHeaderInstructionParameters>
{
};

TEST_P(VerifyHeaderInstruction, VerifyAfterInitializing)
{
    uint8_t header[64];

    auto packet_type = std::get<0>(GetParam());
    auto command_code = std::get<1>(GetParam());
    auto reply_address_unpadded_size = std::get<2>(GetParam());
    auto expected_status = std::get<3>(GetParam());

    ASSERT_EQ(
        rmap_initialize_header(
            header,
            sizeof(header),
            packet_type,
            command_code,
            reply_address_unpadded_size),
        RMAP_OK);

    EXPECT_EQ(rmap_verify_header_instruction(header), expected_status);
}

INSTANTIATE_TEST_SUITE_P(
    ReservedPacketTypes,
    VerifyHeaderInstruction,
    testing::Combine(
        testing::Values(
            RMAP_PACKET_TYPE_COMMAND_RESERVED,
            RMAP_PACKET_TYPE_REPLY_RESERVED),
        testing::Range(
            0,
            (RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_VERIFY |
             RMAP_COMMAND_CODE_REPLY | RMAP_COMMAND_CODE_INCREMENT) +
                1),
        testing::Range((size_t)0, (size_t)(RMAP_REPLY_ADDRESS_LENGTH_MAX + 1)),
        testing::Values(RMAP_UNUSED_PACKET_TYPE)));

INSTANTIATE_TEST_SUITE_P(
    CommandWithUnusedCommandCodes,
    VerifyHeaderInstruction,
    testing::Combine(
        testing::Values(RMAP_PACKET_TYPE_COMMAND),
        testing::Values(
            0,
            RMAP_COMMAND_CODE_INCREMENT,
            RMAP_COMMAND_CODE_VERIFY,
            RMAP_COMMAND_CODE_VERIFY | RMAP_COMMAND_CODE_INCREMENT,
            RMAP_COMMAND_CODE_VERIFY | RMAP_COMMAND_CODE_REPLY),
        testing::Range((size_t)0, (size_t)(RMAP_REPLY_ADDRESS_LENGTH_MAX + 1)),
        testing::Values(RMAP_UNUSED_COMMAND_CODE)));

INSTANTIATE_TEST_SUITE_P(
    ReplyWithoutReplyBit,
    VerifyHeaderInstruction,
    testing::Combine(
        testing::Values(RMAP_PACKET_TYPE_REPLY),
        testing::Values(
            0,
            RMAP_COMMAND_CODE_INCREMENT,
            RMAP_COMMAND_CODE_VERIFY,
            RMAP_COMMAND_CODE_VERIFY | RMAP_COMMAND_CODE_INCREMENT,
            RMAP_COMMAND_CODE_WRITE,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_INCREMENT,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_VERIFY,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_VERIFY |
                RMAP_COMMAND_CODE_INCREMENT),
        testing::Range((size_t)0, (size_t)(RMAP_REPLY_ADDRESS_LENGTH_MAX + 1)),
        testing::Values(RMAP_NO_REPLY)));

INSTANTIATE_TEST_SUITE_P(
    ReplyWithUnusedCommandCodes,
    VerifyHeaderInstruction,
    testing::Combine(
        testing::Values(RMAP_PACKET_TYPE_REPLY),
        testing::Values(RMAP_COMMAND_CODE_VERIFY | RMAP_COMMAND_CODE_REPLY),
        testing::Range((size_t)0, (size_t)(RMAP_REPLY_ADDRESS_LENGTH_MAX + 1)),
        testing::Values(RMAP_UNUSED_COMMAND_CODE)));

INSTANTIATE_TEST_SUITE_P(
    ValidCommands,
    VerifyHeaderInstruction,
    testing::Combine(
        testing::Values(RMAP_PACKET_TYPE_COMMAND),
        testing::Values(
            RMAP_COMMAND_CODE_REPLY,
            RMAP_COMMAND_CODE_REPLY | RMAP_COMMAND_CODE_INCREMENT,
            RMAP_COMMAND_CODE_RMW,
            RMAP_COMMAND_CODE_WRITE,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_INCREMENT,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY |
                RMAP_COMMAND_CODE_INCREMENT,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_VERIFY,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_VERIFY |
                RMAP_COMMAND_CODE_INCREMENT,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_VERIFY |
                RMAP_COMMAND_CODE_REPLY,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_VERIFY |
                RMAP_COMMAND_CODE_REPLY | RMAP_COMMAND_CODE_INCREMENT),
        testing::Range((size_t)0, (size_t)(RMAP_REPLY_ADDRESS_LENGTH_MAX + 1)),
        testing::Values(RMAP_OK)));

INSTANTIATE_TEST_SUITE_P(
    ValidReplies,
    VerifyHeaderInstruction,
    testing::Combine(
        testing::Values(RMAP_PACKET_TYPE_REPLY),
        testing::Values(
            RMAP_COMMAND_CODE_REPLY,
            RMAP_COMMAND_CODE_REPLY | RMAP_COMMAND_CODE_INCREMENT,
            RMAP_COMMAND_CODE_RMW,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY |
                RMAP_COMMAND_CODE_INCREMENT,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_VERIFY |
                RMAP_COMMAND_CODE_REPLY,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_VERIFY |
                RMAP_COMMAND_CODE_REPLY | RMAP_COMMAND_CODE_INCREMENT),
        testing::Range((size_t)0, (size_t)(RMAP_REPLY_ADDRESS_LENGTH_MAX + 1)),
        testing::Values(RMAP_OK)));

typedef std::tuple<size_t, enum rmap_packet_type, int, size_t, enum rmap_status>
    InitializeHeaderParameters;

class InitializeHeader :
    public testing::TestWithParam<InitializeHeaderParameters>
{
};

TEST_P(InitializeHeader, ParameterChecks)
{
    std::vector<uint8_t> buf(RMAP_HEADER_SIZE_MAX + RMAP_DATA_LENGTH_MAX + 1);
    size_t header_offset;

    auto max_size = std::get<0>(GetParam());
    auto packet_type = std::get<1>(GetParam());
    auto command_code = std::get<2>(GetParam());
    auto reply_address_unpadded_size = std::get<3>(GetParam());
    auto expected_status = std::get<4>(GetParam());

    EXPECT_EQ(
        rmap_initialize_header(
            buf.data(),
            max_size,
            packet_type,
            command_code,
            reply_address_unpadded_size),
        expected_status);

    memset(buf.data(), 0, buf.size());
    auto data_offset = max_size;
    EXPECT_EQ(
        rmap_initialize_header_before(
            &header_offset,
            buf.data(),
            data_offset,
            packet_type,
            command_code,
            reply_address_unpadded_size),
        expected_status);
}

INSTANTIATE_TEST_SUITE_P(
    ReservedPacketTypes,
    InitializeHeader,
    testing::Values(
        std::make_tuple(
            64,
            RMAP_PACKET_TYPE_COMMAND_RESERVED,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
            0,
            RMAP_OK),
        std::make_tuple(
            64,
            RMAP_PACKET_TYPE_REPLY_RESERVED,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
            0,
            RMAP_OK)));

INSTANTIATE_TEST_SUITE_P(
    InvalidCommandCodes,
    InitializeHeader,
    testing::Values(
        std::make_tuple(
            64,
            RMAP_PACKET_TYPE_COMMAND,
            -1,
            0,
            RMAP_INVALID_COMMAND_CODE),
        std::make_tuple(
            64,
            RMAP_PACKET_TYPE_COMMAND,
            (RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_VERIFY |
             RMAP_COMMAND_CODE_INCREMENT | RMAP_COMMAND_CODE_REPLY) +
                1,
            0,
            RMAP_INVALID_COMMAND_CODE),
        std::make_tuple(
            64,
            RMAP_PACKET_TYPE_COMMAND,
            0xFF,
            0,
            RMAP_INVALID_COMMAND_CODE)));

INSTANTIATE_TEST_SUITE_P(
    NoReply,
    InitializeHeader,
    testing::Values(std::make_tuple(
        64,
        RMAP_PACKET_TYPE_REPLY,
        RMAP_COMMAND_CODE_WRITE,
        0,
        RMAP_OK)));

INSTANTIATE_TEST_SUITE_P(
    UnusedCommandCodes,
    InitializeHeader,
    testing::Values(
        std::make_tuple(64, RMAP_PACKET_TYPE_COMMAND, 0, 0, RMAP_OK),
        std::make_tuple(
            64,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_INCREMENT,
            0,
            RMAP_OK),
        std::make_tuple(
            64,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_VERIFY,
            0,
            RMAP_OK),
        std::make_tuple(
            64,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_VERIFY | RMAP_COMMAND_CODE_INCREMENT,
            0,
            RMAP_OK),
        std::make_tuple(
            64,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_VERIFY | RMAP_COMMAND_CODE_REPLY,
            0,
            RMAP_OK)));

INSTANTIATE_TEST_SUITE_P(
    ReplyAddressTooLong,
    InitializeHeader,
    testing::Values(
        std::make_tuple(
            64,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
            RMAP_REPLY_ADDRESS_LENGTH_MAX + 1,
            RMAP_REPLY_ADDRESS_TOO_LONG),
        std::make_tuple(
            64,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
            0xFF,
            RMAP_REPLY_ADDRESS_TOO_LONG),
        std::make_tuple(
            64,
            RMAP_PACKET_TYPE_REPLY,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
            RMAP_REPLY_ADDRESS_LENGTH_MAX + 1,
            RMAP_REPLY_ADDRESS_TOO_LONG),
        std::make_tuple(
            64,
            RMAP_PACKET_TYPE_REPLY,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
            0xFF,
            RMAP_REPLY_ADDRESS_TOO_LONG),
        std::make_tuple(
            64,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_REPLY,
            RMAP_REPLY_ADDRESS_LENGTH_MAX + 1,
            RMAP_REPLY_ADDRESS_TOO_LONG),
        std::make_tuple(
            64,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_REPLY,
            0xFF,
            RMAP_REPLY_ADDRESS_TOO_LONG),
        std::make_tuple(
            64,
            RMAP_PACKET_TYPE_REPLY,
            RMAP_COMMAND_CODE_REPLY,
            RMAP_REPLY_ADDRESS_LENGTH_MAX + 1,
            RMAP_REPLY_ADDRESS_TOO_LONG),
        std::make_tuple(
            64,
            RMAP_PACKET_TYPE_REPLY,
            RMAP_COMMAND_CODE_REPLY,
            0xFF,
            RMAP_REPLY_ADDRESS_TOO_LONG),
        std::make_tuple(
            64,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_RMW,
            RMAP_REPLY_ADDRESS_LENGTH_MAX + 1,
            RMAP_REPLY_ADDRESS_TOO_LONG),
        std::make_tuple(
            64,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_RMW,
            0xFF,
            RMAP_REPLY_ADDRESS_TOO_LONG),
        std::make_tuple(
            64,
            RMAP_PACKET_TYPE_REPLY,
            RMAP_COMMAND_CODE_RMW,
            RMAP_REPLY_ADDRESS_LENGTH_MAX + 1,
            RMAP_REPLY_ADDRESS_TOO_LONG),
        std::make_tuple(
            64,
            RMAP_PACKET_TYPE_REPLY,
            RMAP_COMMAND_CODE_RMW,
            0xFF,
            RMAP_REPLY_ADDRESS_TOO_LONG)));

INSTANTIATE_TEST_SUITE_P(
    WriteCommandSizeLimits,
    InitializeHeader,
    testing::Values(
        std::make_tuple(
            RMAP_COMMAND_HEADER_STATIC_SIZE - 1,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
            0,
            RMAP_NOT_ENOUGH_SPACE),
        std::make_tuple(
            RMAP_COMMAND_HEADER_STATIC_SIZE,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
            0,
            RMAP_OK),
        std::make_tuple(
            RMAP_COMMAND_HEADER_STATIC_SIZE,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
            1,
            RMAP_NOT_ENOUGH_SPACE),
        std::make_tuple(
            RMAP_COMMAND_HEADER_STATIC_SIZE + 4 - 1,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
            1,
            RMAP_NOT_ENOUGH_SPACE),
        std::make_tuple(
            RMAP_COMMAND_HEADER_STATIC_SIZE + 4,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
            1,
            RMAP_OK),
        std::make_tuple(
            RMAP_COMMAND_HEADER_STATIC_SIZE + 4,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
            4,
            RMAP_OK),
        std::make_tuple(
            RMAP_COMMAND_HEADER_STATIC_SIZE + 11,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
            9,
            RMAP_NOT_ENOUGH_SPACE),
        std::make_tuple(
            RMAP_COMMAND_HEADER_STATIC_SIZE + 12,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
            9,
            RMAP_OK),
        std::make_tuple(
            RMAP_COMMAND_HEADER_STATIC_SIZE + 12,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
            12,
            RMAP_OK)));

INSTANTIATE_TEST_SUITE_P(
    WriteReplySizeLimits,
    InitializeHeader,
    testing::Values(
        std::make_tuple(
            RMAP_WRITE_REPLY_HEADER_STATIC_SIZE - 1,
            RMAP_PACKET_TYPE_REPLY,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
            0,
            RMAP_NOT_ENOUGH_SPACE),
        std::make_tuple(
            RMAP_WRITE_REPLY_HEADER_STATIC_SIZE - 1,
            RMAP_PACKET_TYPE_REPLY,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
            RMAP_REPLY_ADDRESS_LENGTH_MAX,
            RMAP_NOT_ENOUGH_SPACE),
        std::make_tuple(
            RMAP_WRITE_REPLY_HEADER_STATIC_SIZE,
            RMAP_PACKET_TYPE_REPLY,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
            0,
            RMAP_OK),
        std::make_tuple(
            RMAP_WRITE_REPLY_HEADER_STATIC_SIZE,
            RMAP_PACKET_TYPE_REPLY,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
            RMAP_REPLY_ADDRESS_LENGTH_MAX,
            RMAP_OK)));

INSTANTIATE_TEST_SUITE_P(
    ReadCommandSizeLimits,
    InitializeHeader,
    testing::Values(
        std::make_tuple(
            RMAP_COMMAND_HEADER_STATIC_SIZE - 1,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_REPLY,
            0,
            RMAP_NOT_ENOUGH_SPACE),
        std::make_tuple(
            RMAP_COMMAND_HEADER_STATIC_SIZE,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_REPLY,
            0,
            RMAP_OK),
        std::make_tuple(
            RMAP_COMMAND_HEADER_STATIC_SIZE,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_REPLY,
            1,
            RMAP_NOT_ENOUGH_SPACE),
        std::make_tuple(
            RMAP_COMMAND_HEADER_STATIC_SIZE + 4 - 1,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_REPLY,
            1,
            RMAP_NOT_ENOUGH_SPACE),
        std::make_tuple(
            RMAP_COMMAND_HEADER_STATIC_SIZE + 4,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_REPLY,
            1,
            RMAP_OK),
        std::make_tuple(
            RMAP_COMMAND_HEADER_STATIC_SIZE + 4,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_REPLY,
            4,
            RMAP_OK),
        std::make_tuple(
            RMAP_COMMAND_HEADER_STATIC_SIZE + 11,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_REPLY,
            9,
            RMAP_NOT_ENOUGH_SPACE),
        std::make_tuple(
            RMAP_COMMAND_HEADER_STATIC_SIZE + 12,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_REPLY,
            9,
            RMAP_OK),
        std::make_tuple(
            RMAP_COMMAND_HEADER_STATIC_SIZE + 12,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_REPLY,
            12,
            RMAP_OK)));

INSTANTIATE_TEST_SUITE_P(
    ReadReplySizeLimits,
    InitializeHeader,
    testing::Values(
        std::make_tuple(
            RMAP_READ_REPLY_HEADER_STATIC_SIZE - 1,
            RMAP_PACKET_TYPE_REPLY,
            RMAP_COMMAND_CODE_REPLY,
            0,
            RMAP_NOT_ENOUGH_SPACE),
        std::make_tuple(
            RMAP_READ_REPLY_HEADER_STATIC_SIZE - 1,
            RMAP_PACKET_TYPE_REPLY,
            RMAP_COMMAND_CODE_REPLY,
            RMAP_REPLY_ADDRESS_LENGTH_MAX,
            RMAP_NOT_ENOUGH_SPACE),
        std::make_tuple(
            RMAP_READ_REPLY_HEADER_STATIC_SIZE,
            RMAP_PACKET_TYPE_REPLY,
            RMAP_COMMAND_CODE_REPLY,
            0,
            RMAP_OK),
        std::make_tuple(
            RMAP_READ_REPLY_HEADER_STATIC_SIZE,
            RMAP_PACKET_TYPE_REPLY,
            RMAP_COMMAND_CODE_REPLY,
            RMAP_REPLY_ADDRESS_LENGTH_MAX,
            RMAP_OK)));

INSTANTIATE_TEST_SUITE_P(
    RmwCommandSizeLimits,
    InitializeHeader,
    testing::Values(
        std::make_tuple(
            RMAP_COMMAND_HEADER_STATIC_SIZE - 1,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_RMW,
            0,
            RMAP_NOT_ENOUGH_SPACE),
        std::make_tuple(
            RMAP_COMMAND_HEADER_STATIC_SIZE,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_RMW,
            0,
            RMAP_OK),
        std::make_tuple(
            RMAP_COMMAND_HEADER_STATIC_SIZE,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_RMW,
            1,
            RMAP_NOT_ENOUGH_SPACE),
        std::make_tuple(
            RMAP_COMMAND_HEADER_STATIC_SIZE + 4 - 1,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_RMW,
            1,
            RMAP_NOT_ENOUGH_SPACE),
        std::make_tuple(
            RMAP_COMMAND_HEADER_STATIC_SIZE + 4,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_RMW,
            1,
            RMAP_OK),
        std::make_tuple(
            RMAP_COMMAND_HEADER_STATIC_SIZE + 4,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_RMW,
            4,
            RMAP_OK),
        std::make_tuple(
            RMAP_COMMAND_HEADER_STATIC_SIZE + 11,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_RMW,
            9,
            RMAP_NOT_ENOUGH_SPACE),
        std::make_tuple(
            RMAP_COMMAND_HEADER_STATIC_SIZE + 12,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_RMW,
            9,
            RMAP_OK),
        std::make_tuple(
            RMAP_COMMAND_HEADER_STATIC_SIZE + 12,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_RMW,
            12,
            RMAP_OK)));

INSTANTIATE_TEST_SUITE_P(
    RmwReplySizeLimits,
    InitializeHeader,
    testing::Values(
        std::make_tuple(
            RMAP_READ_REPLY_HEADER_STATIC_SIZE - 1,
            RMAP_PACKET_TYPE_REPLY,
            RMAP_COMMAND_CODE_RMW,
            0,
            RMAP_NOT_ENOUGH_SPACE),
        std::make_tuple(
            RMAP_READ_REPLY_HEADER_STATIC_SIZE - 1,
            RMAP_PACKET_TYPE_REPLY,
            RMAP_COMMAND_CODE_RMW,
            RMAP_REPLY_ADDRESS_LENGTH_MAX,
            RMAP_NOT_ENOUGH_SPACE),
        std::make_tuple(
            RMAP_READ_REPLY_HEADER_STATIC_SIZE,
            RMAP_PACKET_TYPE_REPLY,
            RMAP_COMMAND_CODE_RMW,
            0,
            RMAP_OK),
        std::make_tuple(
            RMAP_READ_REPLY_HEADER_STATIC_SIZE,
            RMAP_PACKET_TYPE_REPLY,
            RMAP_COMMAND_CODE_RMW,
            RMAP_REPLY_ADDRESS_LENGTH_MAX,
            RMAP_OK)));

typedef std::tuple<
    enum rmap_packet_type,
    int,
    size_t,
    uint8_t,
    uint8_t,
    uint16_t,
    uint32_t>
    CreateSuccessReplyFromCommandParameters;

class CreateSuccessReplyFromCommand :
    public testing::TestWithParam<CreateSuccessReplyFromCommandParameters>
{
};

TEST_P(CreateSuccessReplyFromCommand, RmapCreateSuccessReplyFromCommand)
{
    uint8_t command_header[RMAP_HEADER_SIZE_MAX];
    uint8_t reply_packet[RMAP_REPLY_ADDRESS_LENGTH_MAX + RMAP_HEADER_SIZE_MAX];
    size_t reply_header_offset;

    auto command_packet_type = std::get<0>(GetParam());
    auto command_command_code = std::get<1>(GetParam());
    auto command_reply_address_unpadded_size = std::get<2>(GetParam());
    auto command_target_logical_address = std::get<3>(GetParam());
    auto command_initiator_logical_address = std::get<4>(GetParam());
    auto command_transaction_identifier = std::get<5>(GetParam());
    auto command_data_length = std::get<6>(GetParam());

    ASSERT_EQ(
        rmap_initialize_header(
            command_header,
            sizeof(command_header),
            command_packet_type,
            command_command_code,
            command_reply_address_unpadded_size),
        RMAP_OK);

    rmap_set_target_logical_address(
        command_header,
        command_target_logical_address);
    rmap_set_initiator_logical_address(
        command_header,
        command_initiator_logical_address);
    rmap_set_key(command_header, 123);

    const uint8_t reply_address_data[] = {
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,
        0x99,
        0xAA,
        0xBB,
        0xCC,
    };

    rmap_set_reply_address(
        command_header,
        reply_address_data,
        command_reply_address_unpadded_size),

        rmap_set_transaction_identifier(
            command_header,
            command_transaction_identifier);
    rmap_set_extended_address(command_header, 0x12);
    rmap_set_address(command_header, 0x3456789A);
    rmap_set_data_length(command_header, command_data_length);

    ASSERT_EQ(
        rmap_create_success_reply_from_command(
            reply_packet,
            &reply_header_offset,
            sizeof(reply_packet),
            command_header),
        RMAP_OK);

    EXPECT_EQ(reply_header_offset, command_reply_address_unpadded_size);
    EXPECT_EQ(
        rmap_get_initiator_logical_address(reply_packet + reply_header_offset),
        command_initiator_logical_address);
    EXPECT_EQ(rmap_is_command(reply_packet + reply_header_offset), false);
    EXPECT_EQ(
        rmap_is_unused_packet_type(reply_packet + reply_header_offset),
        false);
    EXPECT_EQ(
        std::vector<uint8_t>(reply_packet, reply_packet + reply_header_offset),
        std::vector<uint8_t>(
            reply_address_data,
            reply_address_data + command_reply_address_unpadded_size));
    EXPECT_EQ(
        rmap_get_target_logical_address(reply_packet + reply_header_offset),
        command_target_logical_address);
    EXPECT_EQ(
        rmap_get_transaction_identifier(reply_packet + reply_header_offset),
        command_transaction_identifier);

    if (rmap_is_rmw(command_header)) {
        /* RMW reply contains data length and should be half of command data
         * length.
         */
        EXPECT_EQ(
            rmap_get_data_length(reply_packet + reply_header_offset),
            command_data_length / 2);
    } else if (rmap_is_write(command_header)) {
        /* Write reply contains no data length and will be reported as 0. */
        EXPECT_EQ(rmap_get_data_length(reply_packet + reply_header_offset), 0);

    } else {
        /* Read reply contains data length. */
        EXPECT_EQ(
            rmap_get_data_length(reply_packet + reply_header_offset),
            command_data_length);
    }
}

TEST_P(CreateSuccessReplyFromCommand, RmapCreateSuccessReplyFromCommandBefore)
{
    uint8_t command_header[RMAP_HEADER_SIZE_MAX];
    uint8_t buf[1234];
    size_t reply_offset;
    size_t reply_header_offset;

    auto command_packet_type = std::get<0>(GetParam());
    auto command_command_code = std::get<1>(GetParam());
    auto command_reply_address_unpadded_size = std::get<2>(GetParam());
    auto command_target_logical_address = std::get<3>(GetParam());
    auto command_initiator_logical_address = std::get<4>(GetParam());
    auto command_transaction_identifier = std::get<5>(GetParam());
    auto command_data_length = std::get<6>(GetParam());

    ASSERT_EQ(
        rmap_initialize_header(
            command_header,
            sizeof(command_header),
            command_packet_type,
            command_command_code,
            command_reply_address_unpadded_size),
        RMAP_OK);

    rmap_set_target_logical_address(
        command_header,
        command_target_logical_address);
    rmap_set_initiator_logical_address(
        command_header,
        command_initiator_logical_address);
    rmap_set_key(command_header, 123);

    const uint8_t reply_address_data[] = {
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,
        0x99,
        0xAA,
        0xBB,
        0xCC,
    };

    rmap_set_reply_address(
        command_header,
        reply_address_data,
        command_reply_address_unpadded_size),

        rmap_set_transaction_identifier(
            command_header,
            command_transaction_identifier);
    rmap_set_extended_address(command_header, 0x12);
    rmap_set_address(command_header, 0x3456789A);
    rmap_set_data_length(command_header, command_data_length);

    const size_t data_offset = 123;

    ASSERT_EQ(
        rmap_create_success_reply_from_command_before(
            buf,
            &reply_offset,
            &reply_header_offset,
            data_offset,
            command_header),
        RMAP_OK);

    ASSERT_EQ(
        rmap_verify_header_integrity(
            buf + reply_header_offset,
            data_offset - reply_header_offset),
        RMAP_OK);

    EXPECT_EQ(
        reply_offset,
        reply_header_offset - command_reply_address_unpadded_size);
    EXPECT_EQ(
        rmap_get_initiator_logical_address(buf + reply_header_offset),
        command_initiator_logical_address);
    EXPECT_EQ(rmap_is_command(buf + reply_header_offset), false);
    EXPECT_EQ(rmap_is_unused_packet_type(buf + reply_header_offset), false);
    EXPECT_EQ(
        std::vector<uint8_t>(buf + reply_offset, buf + reply_header_offset),
        std::vector<uint8_t>(
            reply_address_data,
            reply_address_data + command_reply_address_unpadded_size));
    EXPECT_EQ(
        rmap_get_target_logical_address(buf + reply_header_offset),
        command_target_logical_address);
    EXPECT_EQ(
        rmap_get_transaction_identifier(buf + reply_header_offset),
        command_transaction_identifier);

    if (rmap_is_rmw(command_header)) {
        /* RMW reply contains data length and should be half of command data
         * length.
         */
        EXPECT_EQ(
            rmap_get_data_length(buf + reply_header_offset),
            command_data_length / 2);
    } else if (rmap_is_write(command_header)) {
        /* Write reply contains no data length and will be reported as 0. */
        EXPECT_EQ(rmap_get_data_length(buf + reply_header_offset), 0);

    } else {
        /* Read reply contains data length. */
        EXPECT_EQ(
            rmap_get_data_length(buf + reply_header_offset),
            command_data_length);
    }
}

INSTANTIATE_TEST_SUITE_P(
    CommandsWithReply,
    CreateSuccessReplyFromCommand,
    testing::Combine(
        testing::Values(
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_PACKET_TYPE_COMMAND_RESERVED),
        testing::Values(
            RMAP_COMMAND_CODE_REPLY,
            RMAP_COMMAND_CODE_RMW,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY),
        testing::Values(
            (size_t)0,
            (size_t)1,
            (size_t)RMAP_REPLY_ADDRESS_LENGTH_MAX - 1,
            (size_t)RMAP_REPLY_ADDRESS_LENGTH_MAX),
        testing::Values(0x00, 0xFF),
        testing::Values(0x00, 0xFF),
        testing::Values(0, UINT16_MAX),
        testing::Values(0, RMAP_DATA_LENGTH_MAX)));

class CreateSuccessReplyFromCommandSizeLimits :
    public testing::TestWithParam<size_t>
{
};

TEST_P(
    CreateSuccessReplyFromCommandSizeLimits,
    RmapCreateSuccessReplyFromCommandWriteReply)
{
    uint8_t command_header[RMAP_HEADER_SIZE_MAX];
    size_t max_size;
    uint8_t reply_packet[RMAP_REPLY_ADDRESS_LENGTH_MAX + RMAP_HEADER_SIZE_MAX];
    size_t reply_header_offset;

    auto reply_address_unpadded_size = GetParam();

    ASSERT_EQ(
        rmap_initialize_header(
            command_header,
            sizeof(command_header),
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
            reply_address_unpadded_size),
        RMAP_OK);

    rmap_set_target_logical_address(command_header, 0x12);
    rmap_set_initiator_logical_address(command_header, 0x12);
    rmap_set_key(command_header, 123);

    const uint8_t reply_address_data[] = {
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,
        0x99,
        0xAA,
        0xBB,
        0xCC,
    };

    rmap_set_reply_address(
        command_header,
        reply_address_data,
        reply_address_unpadded_size),

        rmap_set_transaction_identifier(command_header, 123);
    rmap_set_extended_address(command_header, 0x12);
    rmap_set_address(command_header, 0x12345678);
    rmap_set_data_length(command_header, 123);

    max_size =
        RMAP_WRITE_REPLY_HEADER_STATIC_SIZE + reply_address_unpadded_size - 1;
    EXPECT_EQ(
        rmap_create_success_reply_from_command(
            reply_packet,
            &reply_header_offset,
            max_size,
            command_header),
        RMAP_NOT_ENOUGH_SPACE);

    max_size =
        RMAP_WRITE_REPLY_HEADER_STATIC_SIZE + reply_address_unpadded_size;
    EXPECT_EQ(
        rmap_create_success_reply_from_command(
            reply_packet,
            &reply_header_offset,
            max_size,
            command_header),
        RMAP_OK);
}

TEST_P(
    CreateSuccessReplyFromCommandSizeLimits,
    RmapCreateSuccessReplyFromCommandReadReply)
{
    uint8_t command_header[RMAP_HEADER_SIZE_MAX];
    size_t max_size;
    uint8_t reply_packet[RMAP_REPLY_ADDRESS_LENGTH_MAX + RMAP_HEADER_SIZE_MAX];
    size_t reply_header_offset;

    auto reply_address_unpadded_size = GetParam();

    ASSERT_EQ(
        rmap_initialize_header(
            command_header,
            sizeof(command_header),
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_REPLY,
            reply_address_unpadded_size),
        RMAP_OK);

    rmap_set_target_logical_address(command_header, 0x12);
    rmap_set_initiator_logical_address(command_header, 0x12);
    rmap_set_key(command_header, 123);

    const uint8_t reply_address_data[] = {
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,
        0x99,
        0xAA,
        0xBB,
        0xCC,
    };

    rmap_set_reply_address(
        command_header,
        reply_address_data,
        reply_address_unpadded_size),

        rmap_set_transaction_identifier(command_header, 123);
    rmap_set_extended_address(command_header, 0x12);
    rmap_set_address(command_header, 0x12345678);
    rmap_set_data_length(command_header, 123);

    max_size =
        RMAP_READ_REPLY_HEADER_STATIC_SIZE + reply_address_unpadded_size - 1;
    EXPECT_EQ(
        rmap_create_success_reply_from_command(
            reply_packet,
            &reply_header_offset,
            max_size,
            command_header),
        RMAP_NOT_ENOUGH_SPACE);

    max_size = RMAP_READ_REPLY_HEADER_STATIC_SIZE + reply_address_unpadded_size;
    EXPECT_EQ(
        rmap_create_success_reply_from_command(
            reply_packet,
            &reply_header_offset,
            max_size,
            command_header),
        RMAP_OK);
}

TEST_P(
    CreateSuccessReplyFromCommandSizeLimits,
    RmapCreateSuccessReplyFromCommandRmwReply)
{
    uint8_t command_header[RMAP_HEADER_SIZE_MAX];
    size_t max_size;
    uint8_t reply_packet[RMAP_REPLY_ADDRESS_LENGTH_MAX + RMAP_HEADER_SIZE_MAX];
    size_t reply_header_offset;

    auto reply_address_unpadded_size = GetParam();

    ASSERT_EQ(
        rmap_initialize_header(
            command_header,
            sizeof(command_header),
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_RMW,
            reply_address_unpadded_size),
        RMAP_OK);

    rmap_set_target_logical_address(command_header, 0x12);
    rmap_set_initiator_logical_address(command_header, 0x12);
    rmap_set_key(command_header, 123);

    const uint8_t reply_address_data[] = {
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,
        0x99,
        0xAA,
        0xBB,
        0xCC,
    };

    rmap_set_reply_address(
        command_header,
        reply_address_data,
        reply_address_unpadded_size),

        rmap_set_transaction_identifier(command_header, 123);
    rmap_set_extended_address(command_header, 0x12);
    rmap_set_address(command_header, 0x12345678);
    rmap_set_data_length(command_header, 6);

    max_size =
        RMAP_READ_REPLY_HEADER_STATIC_SIZE + reply_address_unpadded_size - 1;
    EXPECT_EQ(
        rmap_create_success_reply_from_command(
            reply_packet,
            &reply_header_offset,
            max_size,
            command_header),
        RMAP_NOT_ENOUGH_SPACE);

    max_size = RMAP_READ_REPLY_HEADER_STATIC_SIZE + reply_address_unpadded_size;
    EXPECT_EQ(
        rmap_create_success_reply_from_command(
            reply_packet,
            &reply_header_offset,
            max_size,
            command_header),
        RMAP_OK);
}

TEST_P(
    CreateSuccessReplyFromCommandSizeLimits,
    RmapCreateSuccessReplyFromCommandBeforeWriteReply)
{
    uint8_t command_header[RMAP_HEADER_SIZE_MAX];
    size_t data_offset;
    uint8_t buf[1234];
    size_t reply_offset;
    size_t reply_header_offset;

    auto reply_address_unpadded_size = GetParam();

    ASSERT_EQ(
        rmap_initialize_header(
            command_header,
            sizeof(command_header),
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
            reply_address_unpadded_size),
        RMAP_OK);

    rmap_set_target_logical_address(command_header, 0x12);
    rmap_set_initiator_logical_address(command_header, 0x12);
    rmap_set_key(command_header, 123);

    const uint8_t reply_address_data[] = {
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,
        0x99,
        0xAA,
        0xBB,
        0xCC,
    };

    rmap_set_reply_address(
        command_header,
        reply_address_data,
        reply_address_unpadded_size),

        rmap_set_transaction_identifier(command_header, 123);
    rmap_set_extended_address(command_header, 0x12);
    rmap_set_address(command_header, 0x12345678);
    rmap_set_data_length(command_header, 123);

    data_offset =
        RMAP_WRITE_REPLY_HEADER_STATIC_SIZE + reply_address_unpadded_size - 1;
    EXPECT_EQ(
        rmap_create_success_reply_from_command_before(
            buf,
            &reply_offset,
            &reply_header_offset,
            data_offset,
            command_header),
        RMAP_NOT_ENOUGH_SPACE);

    data_offset =
        RMAP_WRITE_REPLY_HEADER_STATIC_SIZE + reply_address_unpadded_size;
    EXPECT_EQ(
        rmap_create_success_reply_from_command_before(
            buf,
            &reply_offset,
            &reply_header_offset,
            data_offset,
            command_header),
        RMAP_OK);
}

TEST_P(
    CreateSuccessReplyFromCommandSizeLimits,
    RmapCreateSuccessReplyFromCommandBeforeReadReply)
{
    uint8_t command_header[RMAP_HEADER_SIZE_MAX];
    size_t data_offset;
    uint8_t buf[1234];
    size_t reply_offset;
    size_t reply_header_offset;

    auto reply_address_unpadded_size = GetParam();

    ASSERT_EQ(
        rmap_initialize_header(
            command_header,
            sizeof(command_header),
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_REPLY,
            reply_address_unpadded_size),
        RMAP_OK);

    rmap_set_target_logical_address(command_header, 0x12);
    rmap_set_initiator_logical_address(command_header, 0x12);
    rmap_set_key(command_header, 123);

    const uint8_t reply_address_data[] = {
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,
        0x99,
        0xAA,
        0xBB,
        0xCC,
    };

    rmap_set_reply_address(
        command_header,
        reply_address_data,
        reply_address_unpadded_size),

        rmap_set_transaction_identifier(command_header, 123);
    rmap_set_extended_address(command_header, 0x12);
    rmap_set_address(command_header, 0x12345678);
    rmap_set_data_length(command_header, 123);

    data_offset =
        RMAP_READ_REPLY_HEADER_STATIC_SIZE + reply_address_unpadded_size - 1;
    EXPECT_EQ(
        rmap_create_success_reply_from_command_before(
            buf,
            &reply_offset,
            &reply_header_offset,
            data_offset,
            command_header),
        RMAP_NOT_ENOUGH_SPACE);

    data_offset =
        RMAP_READ_REPLY_HEADER_STATIC_SIZE + reply_address_unpadded_size;
    EXPECT_EQ(
        rmap_create_success_reply_from_command_before(
            buf,
            &reply_offset,
            &reply_header_offset,
            data_offset,
            command_header),
        RMAP_OK);
}

TEST_P(
    CreateSuccessReplyFromCommandSizeLimits,
    RmapCreateSuccessReplyFromCommandBeforeRmwReply)
{
    uint8_t command_header[RMAP_HEADER_SIZE_MAX];
    size_t data_offset;
    uint8_t buf[1234];
    size_t reply_offset;
    size_t reply_header_offset;

    auto reply_address_unpadded_size = GetParam();

    ASSERT_EQ(
        rmap_initialize_header(
            command_header,
            sizeof(command_header),
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_RMW,
            reply_address_unpadded_size),
        RMAP_OK);

    rmap_set_target_logical_address(command_header, 0x12);
    rmap_set_initiator_logical_address(command_header, 0x12);
    rmap_set_key(command_header, 123);

    const uint8_t reply_address_data[] = {
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,
        0x99,
        0xAA,
        0xBB,
        0xCC,
    };

    rmap_set_reply_address(
        command_header,
        reply_address_data,
        reply_address_unpadded_size),

        rmap_set_transaction_identifier(command_header, 123);
    rmap_set_extended_address(command_header, 0x12);
    rmap_set_address(command_header, 0x12345678);
    rmap_set_data_length(command_header, 6);

    data_offset =
        RMAP_READ_REPLY_HEADER_STATIC_SIZE + reply_address_unpadded_size - 1;
    EXPECT_EQ(
        rmap_create_success_reply_from_command_before(
            buf,
            &reply_offset,
            &reply_header_offset,
            data_offset,
            command_header),
        RMAP_NOT_ENOUGH_SPACE);

    data_offset =
        RMAP_READ_REPLY_HEADER_STATIC_SIZE + reply_address_unpadded_size;
    EXPECT_EQ(
        rmap_create_success_reply_from_command_before(
            buf,
            &reply_offset,
            &reply_header_offset,
            data_offset,
            command_header),
        RMAP_OK);
}

INSTANTIATE_TEST_SUITE_P(
    ReplyAddressSizes,
    CreateSuccessReplyFromCommandSizeLimits,
    testing::Range((size_t)0, (size_t)(RMAP_REPLY_ADDRESS_LENGTH_MAX + 1)));

TEST(RmapCreateSuccessReplyFromCommand, WriteCommandWithoutReply)
{
    uint8_t command_header[RMAP_HEADER_SIZE_MAX];
    uint8_t reply_packet[RMAP_REPLY_ADDRESS_LENGTH_MAX + RMAP_HEADER_SIZE_MAX];
    size_t reply_header_offset;

    const size_t reply_address_unpadded_size = 0;
    ASSERT_EQ(
        rmap_initialize_header(
            command_header,
            sizeof(command_header),
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_WRITE,
            reply_address_unpadded_size),
        RMAP_OK);

    rmap_set_target_logical_address(command_header, 0x12);
    rmap_set_initiator_logical_address(command_header, 0x12);
    rmap_set_key(command_header, 123);
    rmap_set_transaction_identifier(command_header, 123);
    rmap_set_extended_address(command_header, 0x12);
    rmap_set_address(command_header, 0x12345678);
    rmap_set_data_length(command_header, 123);

    EXPECT_EQ(
        rmap_create_success_reply_from_command(
            reply_packet,
            &reply_header_offset,
            sizeof(reply_packet),
            command_header),
        RMAP_NO_REPLY);
}

TEST(RmapCreateSuccessReplyFromCommand, ReadCommandWithoutReply)
{
    uint8_t command_header[RMAP_HEADER_SIZE_MAX];
    uint8_t reply_packet[RMAP_REPLY_ADDRESS_LENGTH_MAX + RMAP_HEADER_SIZE_MAX];
    size_t reply_header_offset;

    const size_t reply_address_unpadded_size = 0;
    const int command_code = 0;
    ASSERT_EQ(
        rmap_initialize_header(
            command_header,
            sizeof(command_header),
            RMAP_PACKET_TYPE_COMMAND,
            command_code,
            reply_address_unpadded_size),
        RMAP_OK);

    rmap_set_target_logical_address(command_header, 0x12);
    rmap_set_initiator_logical_address(command_header, 0x12);
    rmap_set_key(command_header, 123);
    rmap_set_transaction_identifier(command_header, 123);
    rmap_set_extended_address(command_header, 0x12);
    rmap_set_address(command_header, 0x12345678);
    rmap_set_data_length(command_header, 123);

    EXPECT_EQ(
        rmap_create_success_reply_from_command(
            reply_packet,
            &reply_header_offset,
            sizeof(reply_packet),
            command_header),
        RMAP_NO_REPLY);
}

TEST_P(TestPatternCommandReplyPairs, RecreateReply)
{
    std::vector<uint8_t> buf(123);
    size_t reply_header_offset;

    const auto command_pattern = std::get<0>(GetParam());
    const std::vector<uint8_t> command_packet =
        command_pattern.packet_without_spacewire_address_prefix();

    EXPECT_EQ(
        rmap_create_success_reply_from_command(
            buf.data(),
            &reply_header_offset,
            buf.size(),
            command_packet.data()),
        RMAP_OK);

    const auto reply_pattern = std::get<1>(GetParam());
    const std::vector<uint8_t> data = reply_pattern.data_field();

    const size_t reply_header_size =
        rmap_calculate_header_size(buf.data() + reply_header_offset);
    buf.resize(reply_header_offset + reply_header_size);
    if (data.size() > 0) {
        buf.insert(buf.end(), data.begin(), data.end());
        buf.push_back(rmap_crc_calculate(data.data(), data.size()));
    }

    EXPECT_EQ(buf, reply_pattern.data);
}

TEST_P(TestPatternCommandReplyPairs, RecreateReplyBefore)
{
    std::vector<uint8_t> buf(123);
    size_t reply_offset;
    size_t reply_header_offset;
    std::vector<uint8_t> reply;

    const auto command_pattern = std::get<0>(GetParam());
    const std::vector<uint8_t> command_packet =
        command_pattern.packet_without_spacewire_address_prefix();

    const auto reply_pattern = std::get<1>(GetParam());
    const size_t data_offset =
        RMAP_REPLY_ADDRESS_LENGTH_MAX + RMAP_HEADER_SIZE_MAX;
    const std::vector<uint8_t> data = reply_pattern.data_field();
    if (!rmap_is_write(
            reply_pattern.data.data() + reply_pattern.header_offset)) {
        /* All packets except write replies have data field. */
        std::copy(data.begin(), data.end(), buf.begin() + data_offset);
        buf.at(data_offset + data.size()) =
            rmap_crc_calculate(data.data(), data.size());
    }

    EXPECT_EQ(
        rmap_create_success_reply_from_command_before(
            buf.data(),
            &reply_offset,
            &reply_header_offset,
            data_offset,
            command_packet.data()),
        RMAP_OK);

    const size_t reply_header_size =
        rmap_calculate_header_size(buf.data() + reply_header_offset);
    if (rmap_is_write(
            reply_pattern.data.data() + reply_pattern.header_offset)) {
        /* Write replies have no data field. */
        reply = std::vector<uint8_t>(
            buf.begin() + reply_offset,
            buf.begin() + reply_header_offset + reply_header_size);
    } else {
        /* All packets except write replies have data field. */
        reply = std::vector<uint8_t>(
            buf.begin() + reply_offset,
            buf.begin() + reply_header_offset + reply_header_size +
                data.size() + 1);
    }
    EXPECT_EQ(reply, reply_pattern.data);
}

TEST(RmapCreateSuccessReplyFromCommandBefore, WriteCommandWithoutReply)
{
    uint8_t command_header[RMAP_HEADER_SIZE_MAX];
    uint8_t buf[1234];
    size_t reply_offset;
    size_t reply_header_offset;

    const size_t reply_address_unpadded_size = 0;
    ASSERT_EQ(
        rmap_initialize_header(
            command_header,
            sizeof(command_header),
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_WRITE,
            reply_address_unpadded_size),
        RMAP_OK);

    rmap_set_target_logical_address(command_header, 0x12);
    rmap_set_initiator_logical_address(command_header, 0x12);
    rmap_set_key(command_header, 123);
    rmap_set_transaction_identifier(command_header, 123);
    rmap_set_extended_address(command_header, 0x12);
    rmap_set_address(command_header, 0x12345678);
    rmap_set_data_length(command_header, 123);

    const size_t data_offset = 123;

    EXPECT_EQ(
        rmap_create_success_reply_from_command_before(
            buf,
            &reply_offset,
            &reply_header_offset,
            data_offset,
            command_header),
        RMAP_NO_REPLY);
}

TEST(RmapCreateSuccessReplyFromCommandBefore, ReadCommandWithoutReply)
{
    uint8_t command_header[RMAP_HEADER_SIZE_MAX];
    uint8_t buf[1234];
    size_t reply_offset;
    size_t reply_header_offset;

    const size_t reply_address_unpadded_size = 0;
    const int command_code = 0;
    ASSERT_EQ(
        rmap_initialize_header(
            command_header,
            sizeof(command_header),
            RMAP_PACKET_TYPE_COMMAND,
            command_code,
            reply_address_unpadded_size),
        RMAP_OK);

    rmap_set_target_logical_address(command_header, 0x12);
    rmap_set_initiator_logical_address(command_header, 0x12);
    rmap_set_key(command_header, 123);
    rmap_set_transaction_identifier(command_header, 123);
    rmap_set_extended_address(command_header, 0x12);
    rmap_set_address(command_header, 0x12345678);
    rmap_set_data_length(command_header, 123);

    const size_t data_offset = 123;

    EXPECT_EQ(
        rmap_create_success_reply_from_command_before(
            buf,
            &reply_offset,
            &reply_header_offset,
            data_offset,
            command_header),
        RMAP_NO_REPLY);
}

TEST(RmapRecreateHeader, TestPattern0Command)
{
    size_t header_offset;
    uint8_t buf[1234];

    const auto pattern = test_pattern0_unverified_incrementing_write_with_reply;

    const std::vector<uint8_t> expected_packet = pattern.data;

    memset(buf, 0, sizeof(buf));

    const std::vector<uint8_t> data = pattern.data_field();

    const size_t data_offset = 123;

    memcpy(buf + data_offset, data.data(), data.size());

    EXPECT_EQ(
        rmap_initialize_header_before(
            &header_offset,
            buf,
            data_offset,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY |
                RMAP_COMMAND_CODE_INCREMENT,
            0),
        RMAP_OK);

    uint8_t *const header = buf + header_offset;

    rmap_set_target_logical_address(header, 0xFE);
    rmap_set_key(header, 0);
    rmap_set_initiator_logical_address(header, 0x67);
    rmap_set_transaction_identifier(header, 0);
    rmap_set_extended_address(header, 0x00);
    rmap_set_address(header, 0xA0000000);
    rmap_set_data_length(header, data.size());

    rmap_calculate_and_set_header_crc(header);

    buf[data_offset + data.size()] =
        rmap_crc_calculate(buf + data_offset, data.size());

    const std::vector<uint8_t> packet(
        buf + header_offset,
        buf + data_offset + data.size() + 1);
    EXPECT_EQ(packet, expected_packet);
}

TEST(RmapRecreateHeader, TestPattern0Reply)
{
    uint8_t buf[123];

    const auto pattern = test_pattern0_expected_write_reply;

    const std::vector<uint8_t> expected_packet = pattern.data;

    memset(buf, 0, sizeof(buf));

    EXPECT_EQ(
        rmap_initialize_header(
            buf,
            sizeof(buf),
            RMAP_PACKET_TYPE_REPLY,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY |
                RMAP_COMMAND_CODE_INCREMENT,
            0),
        RMAP_OK);

    rmap_set_initiator_logical_address(buf, 0x67);
    rmap_set_status(buf, RMAP_STATUS_FIELD_CODE_SUCCESS);
    rmap_set_target_logical_address(buf, 0xFE);
    rmap_set_transaction_identifier(buf, 0);
    rmap_calculate_and_set_header_crc(buf);

    const std::vector<uint8_t> packet(
        buf,
        buf + rmap_calculate_header_size(buf));
    EXPECT_EQ(packet, expected_packet);
}

TEST(RmapRecreateHeader, TestPattern1Command)
{
    uint8_t buf[123];

    const auto pattern = test_pattern1_incrementing_read;

    const std::vector<uint8_t> expected_packet = pattern.data;

    memset(buf, 0, sizeof(buf));

    EXPECT_EQ(
        rmap_initialize_header(
            buf,
            sizeof(buf),
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_REPLY | RMAP_COMMAND_CODE_INCREMENT,
            0),
        RMAP_OK);

    rmap_set_target_logical_address(buf, 0xFE);
    rmap_set_key(buf, 0);
    rmap_set_initiator_logical_address(buf, 0x67);
    rmap_set_transaction_identifier(buf, 1);
    rmap_set_extended_address(buf, 0x00);
    rmap_set_address(buf, 0xA0000000);
    rmap_set_data_length(buf, 16);

    rmap_calculate_and_set_header_crc(buf);

    std::vector<uint8_t> packet(buf, buf + rmap_calculate_header_size(buf));
    EXPECT_EQ(packet, expected_packet);
}

TEST(RmapRecreateHeader, TestPattern1Reply)
{
    size_t header_offset;
    uint8_t buf[1234];

    const auto pattern = test_pattern1_expected_read_reply;

    const std::vector<uint8_t> expected_packet = pattern.data;

    memset(buf, 0, sizeof(buf));

    const std::vector<uint8_t> data = pattern.data_field();

    const size_t data_offset = 123;

    memcpy(buf + data_offset, data.data(), data.size());

    EXPECT_EQ(
        rmap_initialize_header_before(
            &header_offset,
            buf,
            data_offset,
            RMAP_PACKET_TYPE_REPLY,
            RMAP_COMMAND_CODE_REPLY | RMAP_COMMAND_CODE_INCREMENT,
            0),
        RMAP_OK);

    uint8_t *const header = buf + header_offset;

    rmap_set_initiator_logical_address(header, 0x67);
    rmap_set_status(header, RMAP_STATUS_FIELD_CODE_SUCCESS);
    rmap_set_target_logical_address(header, 0xFE);
    rmap_set_transaction_identifier(header, 1);
    rmap_set_reserved(header);
    rmap_set_data_length(header, data.size());

    rmap_calculate_and_set_header_crc(header);

    buf[data_offset + data.size()] =
        rmap_crc_calculate(buf + data_offset, data.size());

    const std::vector<uint8_t> packet(
        buf + header_offset,
        buf + data_offset + data.size() + 1);
    EXPECT_EQ(packet, expected_packet);
}

TEST(RmapRecreateHeader, TestPattern2Command)
{
    size_t header_offset;
    uint8_t buf[1234];

    const auto pattern =
        test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses;

    const std::vector<uint8_t> expected_packet = pattern.data;

    memset(buf, 0, sizeof(buf));

    const std::vector<uint8_t> data = pattern.data_field();

    const size_t data_offset = 123;

    memcpy(buf + data_offset, data.data(), data.size());

    const uint8_t reply_address[] = {0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x00};

    EXPECT_EQ(
        rmap_initialize_header_before(
            &header_offset,
            buf,
            data_offset,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY |
                RMAP_COMMAND_CODE_INCREMENT,
            sizeof(reply_address)),
        RMAP_OK);

    uint8_t *const header = buf + header_offset;

    rmap_set_target_logical_address(header, 0xFE);
    rmap_set_key(header, 0);
    rmap_set_reply_address(header, reply_address, sizeof(reply_address));
    rmap_set_initiator_logical_address(header, 0x67);
    rmap_set_transaction_identifier(header, 2);
    rmap_set_extended_address(header, 0x00);
    rmap_set_address(header, 0xA0000010);
    rmap_set_data_length(header, data.size());

    rmap_calculate_and_set_header_crc(header);

    buf[data_offset + data.size()] =
        rmap_crc_calculate(buf + data_offset, data.size());

    const std::vector<uint8_t> target_address(
        pattern.data.begin(),
        pattern.data.begin() + pattern.header_offset);

    memcpy(
        header - target_address.size(),
        target_address.data(),
        target_address.size());

    const std::vector<uint8_t> packet(
        buf + header_offset - target_address.size(),
        buf + data_offset + data.size() + 1);
    EXPECT_EQ(packet, expected_packet);
}

TEST(RmapRecreateHeader, TestPattern2Reply)
{
    uint8_t buf[123];

    const auto pattern =
        test_pattern2_expected_write_reply_with_spacewire_addresses;

    const std::vector<uint8_t> expected_packet = pattern.data;

    memset(buf, 0, sizeof(buf));

    const std::vector<uint8_t> reply_address(
        pattern.data.begin(),
        pattern.data.begin() + pattern.reply_address_length);

    uint8_t *const header = buf + reply_address.size();

    EXPECT_EQ(
        rmap_initialize_header(
            header,
            sizeof(buf) - reply_address.size(),
            RMAP_PACKET_TYPE_REPLY,
            RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY |
                RMAP_COMMAND_CODE_INCREMENT,
            reply_address.size()),
        RMAP_OK);

    rmap_set_initiator_logical_address(header, 0x67);
    rmap_set_status(header, RMAP_STATUS_FIELD_CODE_SUCCESS);
    rmap_set_target_logical_address(header, 0xFE);
    rmap_set_transaction_identifier(header, 2);
    rmap_calculate_and_set_header_crc(header);

    memcpy(
        header - reply_address.size(),
        reply_address.data(),
        reply_address.size());

    const std::vector<uint8_t> packet(
        buf,
        buf + reply_address.size() + rmap_calculate_header_size(header));
    EXPECT_EQ(packet, expected_packet);
}

TEST(RmapRecreateHeader, TestPattern3Command)
{
    uint8_t buf[123];

    const auto pattern =
        test_pattern3_incrementing_read_with_spacewire_addresses;

    const std::vector<uint8_t> expected_packet = pattern.data;

    memset(buf, 0, sizeof(buf));

    const uint8_t reply_address[] = {0x99, 0xAA, 0xBB, 0xCC};

    const std::vector<uint8_t> target_address(
        pattern.data.begin(),
        pattern.data.begin() + pattern.header_offset);

    uint8_t *const header = buf + target_address.size();

    EXPECT_EQ(
        rmap_initialize_header(
            header,
            sizeof(buf) - target_address.size(),
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_REPLY | RMAP_COMMAND_CODE_INCREMENT,
            sizeof(reply_address)),
        RMAP_OK);

    rmap_set_target_logical_address(header, 0xFE);
    rmap_set_key(header, 0);
    rmap_set_reply_address(header, reply_address, sizeof(reply_address));
    rmap_set_initiator_logical_address(header, 0x67);
    rmap_set_transaction_identifier(header, 3);
    rmap_set_extended_address(header, 0x00);
    rmap_set_address(header, 0xA0000010);
    rmap_set_data_length(header, 16);

    rmap_calculate_and_set_header_crc(header);

    memcpy(
        header - target_address.size(),
        target_address.data(),
        target_address.size());

    const std::vector<uint8_t> packet(
        buf,
        buf + target_address.size() + rmap_calculate_header_size(header));
    EXPECT_EQ(packet, expected_packet);
}

TEST(RmapRecreateHeader, TestPattern3Reply)
{
    size_t header_offset;
    uint8_t buf[1234];

    const auto pattern =
        test_pattern3_expected_read_reply_with_spacewire_addresses;

    const std::vector<uint8_t> expected_packet = pattern.data;

    memset(buf, 0, sizeof(buf));

    const std::vector<uint8_t> data = pattern.data_field();

    const size_t data_offset = 123;

    memcpy(buf + data_offset, data.data(), data.size());

    const std::vector<uint8_t> reply_address(
        pattern.data.begin(),
        pattern.data.begin() + pattern.reply_address_length);

    EXPECT_EQ(
        rmap_initialize_header_before(
            &header_offset,
            buf,
            data_offset,
            RMAP_PACKET_TYPE_REPLY,
            RMAP_COMMAND_CODE_REPLY | RMAP_COMMAND_CODE_INCREMENT,
            reply_address.size()),
        RMAP_OK);

    uint8_t *const header = buf + header_offset;

    rmap_set_initiator_logical_address(header, 0x67);
    rmap_set_status(header, RMAP_STATUS_FIELD_CODE_SUCCESS);
    rmap_set_target_logical_address(header, 0xFE);
    rmap_set_transaction_identifier(header, 3);
    rmap_set_reserved(header);
    rmap_set_data_length(header, data.size());

    rmap_calculate_and_set_header_crc(header);

    memcpy(
        header - reply_address.size(),
        reply_address.data(),
        reply_address.size());

    buf[data_offset + data.size()] =
        rmap_crc_calculate(buf + data_offset, data.size());

    const std::vector<uint8_t> packet(
        buf + header_offset - reply_address.size(),
        buf + data_offset + data.size() + 1);
    EXPECT_EQ(packet, expected_packet);
}

TEST(RmapRecreateHeader, TestPattern4Command)
{
    size_t header_offset;
    uint8_t buf[1234];

    const auto pattern = test_pattern4_rmw;

    const std::vector<uint8_t> expected_packet = pattern.data;

    memset(buf, 0, sizeof(buf));

    const std::vector<uint8_t> data = pattern.data_field();

    const size_t data_offset = 123;

    memcpy(buf + data_offset, data.data(), data.size());

    EXPECT_EQ(
        rmap_initialize_header_before(
            &header_offset,
            buf,
            data_offset,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_RMW,
            0),
        RMAP_OK);

    uint8_t *const header = buf + header_offset;

    rmap_set_target_logical_address(header, 0xFE);
    rmap_set_key(header, 0);
    rmap_set_initiator_logical_address(header, 0x67);
    rmap_set_transaction_identifier(header, 4);
    rmap_set_extended_address(header, 0x00);
    rmap_set_address(header, 0xA0000010);
    rmap_set_data_length(header, data.size());

    rmap_calculate_and_set_header_crc(header);

    buf[data_offset + data.size()] =
        rmap_crc_calculate(buf + data_offset, data.size());

    const std::vector<uint8_t> packet(
        buf + header_offset,
        buf + data_offset + data.size() + 1);
    EXPECT_EQ(packet, expected_packet);
}

TEST(RmapRecreateHeader, TestPattern4Reply)
{
    size_t header_offset;
    uint8_t buf[1234];

    const auto pattern = test_pattern4_expected_rmw_reply;

    const std::vector<uint8_t> expected_packet = pattern.data;

    memset(buf, 0, sizeof(buf));

    const std::vector<uint8_t> data = pattern.data_field();

    const size_t data_offset = 123;

    memcpy(buf + data_offset, data.data(), data.size());

    EXPECT_EQ(
        rmap_initialize_header_before(
            &header_offset,
            buf,
            data_offset,
            RMAP_PACKET_TYPE_REPLY,
            RMAP_COMMAND_CODE_RMW,
            0),
        RMAP_OK);

    uint8_t *const header = buf + header_offset;

    rmap_set_initiator_logical_address(header, 0x67);
    rmap_set_status(header, RMAP_STATUS_FIELD_CODE_SUCCESS);
    rmap_set_target_logical_address(header, 0xFE);
    rmap_set_transaction_identifier(header, 4);
    rmap_set_reserved(header);
    rmap_set_data_length(header, data.size());

    rmap_calculate_and_set_header_crc(header);

    buf[data_offset + data.size()] =
        rmap_crc_calculate(buf + data_offset, data.size());

    const std::vector<uint8_t> packet(
        buf + header_offset,
        buf + data_offset + data.size() + 1);
    EXPECT_EQ(packet, expected_packet);
}

TEST(RmapRecreateHeader, TestPattern5Command)
{
    size_t header_offset;
    uint8_t buf[1234];

    const auto pattern = test_pattern5_rmw_with_spacewire_addresses;

    const std::vector<uint8_t> expected_packet = pattern.data;

    memset(buf, 0, sizeof(buf));

    const std::vector<uint8_t> data = pattern.data_field();

    const size_t data_offset = 123;

    memcpy(buf + data_offset, data.data(), data.size());

    const uint8_t reply_address[] = {0x88};

    EXPECT_EQ(
        rmap_initialize_header_before(
            &header_offset,
            buf,
            data_offset,
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_RMW,
            sizeof(reply_address)),
        RMAP_OK);

    uint8_t *const header = buf + header_offset;

    rmap_set_target_logical_address(header, 0xFE);
    rmap_set_key(header, 0);
    rmap_set_reply_address(header, reply_address, sizeof(reply_address));
    rmap_set_initiator_logical_address(header, 0x67);
    rmap_set_transaction_identifier(header, 5);
    rmap_set_extended_address(header, 0x00);
    rmap_set_address(header, 0xA0000010);
    rmap_set_data_length(header, data.size());

    rmap_calculate_and_set_header_crc(header);

    buf[data_offset + data.size()] =
        rmap_crc_calculate(buf + data_offset, data.size());

    const std::vector<uint8_t> target_address(
        pattern.data.begin(),
        pattern.data.begin() + pattern.header_offset);

    memcpy(
        header - target_address.size(),
        target_address.data(),
        target_address.size());

    std::vector<uint8_t> packet(
        buf + header_offset - target_address.size(),
        buf + data_offset + data.size() + 1);
    EXPECT_EQ(packet, expected_packet);
}

TEST(RmapRecreateHeader, TestPattern5Reply)
{
    size_t header_offset;
    uint8_t buf[1234];

    const auto pattern =
        test_pattern5_expected_rmw_reply_with_spacewire_addresses;

    const std::vector<uint8_t> expected_packet = pattern.data;

    memset(buf, 0, sizeof(buf));

    const std::vector<uint8_t> data = pattern.data_field();

    const size_t data_offset = 123;

    memcpy(buf + data_offset, data.data(), data.size());

    const std::vector<uint8_t> reply_address(
        pattern.data.begin(),
        pattern.data.begin() + pattern.reply_address_length);

    EXPECT_EQ(
        rmap_initialize_header_before(
            &header_offset,
            buf,
            data_offset,
            RMAP_PACKET_TYPE_REPLY,
            RMAP_COMMAND_CODE_RMW,
            reply_address.size()),
        RMAP_OK);

    uint8_t *const header = buf + header_offset;

    rmap_set_initiator_logical_address(header, 0x67);
    rmap_set_status(header, RMAP_STATUS_FIELD_CODE_SUCCESS);
    rmap_set_target_logical_address(header, 0xFE);
    rmap_set_transaction_identifier(header, 5);
    rmap_set_reserved(header);
    rmap_set_data_length(header, data.size());

    rmap_calculate_and_set_header_crc(header);

    memcpy(
        header - reply_address.size(),
        reply_address.data(),
        reply_address.size());

    buf[data_offset + data.size()] =
        rmap_crc_calculate(buf + data_offset, data.size());

    std::vector<uint8_t> packet(
        buf + header_offset - reply_address.size(),
        buf + data_offset + data.size() + 1);
    EXPECT_EQ(packet, expected_packet);
}

TEST(RmapStatusText, StatusFieldCodes)
{
    const std::map<enum rmap_status_field_code, std::string> map = {
        {
            RMAP_STATUS_FIELD_CODE_SUCCESS,
            "RMAP_STATUS_FIELD_CODE_SUCCESS/RMAP_OK",
        },
        {
            RMAP_STATUS_FIELD_CODE_GENERAL_ERROR_CODE,
            "RMAP_STATUS_FIELD_CODE_GENERAL_ERROR_CODE",
        },
        {
            RMAP_STATUS_FIELD_CODE_UNUSED_PACKET_TYPE_OR_COMMAND_CODE,
            "RMAP_STATUS_FIELD_CODE_UNUSED_PACKET_TYPE_OR_COMMAND_CODE",
        },
        {
            RMAP_STATUS_FIELD_CODE_INVALID_KEY,
            "RMAP_STATUS_FIELD_CODE_INVALID_KEY",
        },
        {
            RMAP_STATUS_FIELD_CODE_INVALID_DATA_CRC,
            "RMAP_STATUS_FIELD_CODE_INVALID_DATA_CRC",
        },
        {
            RMAP_STATUS_FIELD_CODE_EARLY_EOP,
            "RMAP_STATUS_FIELD_CODE_EARLY_EOP",
        },
        {
            RMAP_STATUS_FIELD_CODE_TOO_MUCH_DATA,
            "RMAP_STATUS_FIELD_CODE_TOO_MUCH_DATA",
        },
        {
            RMAP_STATUS_FIELD_CODE_EEP,
            "RMAP_STATUS_FIELD_CODE_EEP",
        },
        {
            RMAP_STATUS_FIELD_CODE_VERIFY_BUFFER_OVERRUN,
            "RMAP_STATUS_FIELD_CODE_VERIFY_BUFFER_OVERRUN",
        },
        {
            RMAP_STATUS_FIELD_CODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED,
            "RMAP_STATUS_FIELD_CODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED",
        },
        {
            RMAP_STATUS_FIELD_CODE_RMW_DATA_LENGTH_ERROR,
            "RMAP_STATUS_FIELD_CODE_RMW_DATA_LENGTH_ERROR",
        },
        {
            RMAP_STATUS_FIELD_CODE_INVALID_TARGET_LOGICAL_ADDRESS,
            "RMAP_STATUS_FIELD_CODE_INVALID_TARGET_LOGICAL_ADDRESS",
        },
    };

    for (const auto &entry : map) {
        EXPECT_THAT(
            rmap_status_text(entry.first),
            testing::StrEq(entry.second));
    }
}

TEST(RmapStatusText, Statuses)
{
    EXPECT_THAT(
        rmap_status_text(RMAP_OK),
        testing::StrEq("RMAP_STATUS_FIELD_CODE_SUCCESS/RMAP_OK"));

    /* Excluding RMAP_OK since not in continuous range. */
    const int statuses_first = RMAP_INCOMPLETE_HEADER;
    const rmap_status statuses_last = RMAP_NOT_ENOUGH_SPACE;

    const int statuses_count = statuses_last + 1 - statuses_first;
    std::vector<int> statuses(statuses_count);
    std::iota(statuses.begin(), statuses.end(), statuses_first);

    for (const auto status : statuses) {
        const char *const text = rmap_status_text(status);
        EXPECT_THAT(text, testing::StartsWith("RMAP_"));
    }
}

TEST(RmapStatusText, InvalidStatuses)
{
    EXPECT_THAT(rmap_status_text(8), testing::StrEq("INVALID_STATUS"));
    EXPECT_THAT(rmap_status_text(123), testing::StrEq("INVALID_STATUS"));
    EXPECT_THAT(rmap_status_text(1234), testing::StrEq("INVALID_STATUS"));
}

TEST(RmapCrcCalculate, ZeroesInDataGivesZeroCrc)
{
    unsigned char data[17] = {};

    EXPECT_EQ(rmap_crc_calculate(data, sizeof(data)), 0x00);
}

TEST_P(TestPatternsWithoutData, RmapCrcCalculate)
{
    const auto pattern = GetParam();

    const std::vector<uint8_t> packet =
        pattern.packet_without_spacewire_address_prefix();

    const size_t header_size = rmap_calculate_header_size(packet.data());
    const uint8_t received_crc = packet.at(header_size - 1);
    const uint8_t calculated_excluding_received_crc =
        rmap_crc_calculate(packet.data(), header_size - 1);
    EXPECT_EQ(calculated_excluding_received_crc, received_crc);

    const uint8_t calculated_including_received_crc =
        rmap_crc_calculate(packet.data(), header_size);
    EXPECT_EQ(calculated_including_received_crc, 0);
}

TEST_P(TestPatternsWithData, RmapCrcCalculate)
{
    const auto pattern = GetParam();

    const std::vector<uint8_t> packet =
        pattern.packet_without_spacewire_address_prefix();

    const size_t header_size = rmap_calculate_header_size(packet.data());
    const uint8_t received_header_crc = packet.at(header_size - 1);
    const uint8_t calculated_excluding_received_header_crc =
        rmap_crc_calculate(packet.data(), header_size - 1);
    EXPECT_EQ(calculated_excluding_received_header_crc, received_header_crc);

    const uint8_t calculated_including_received_header_crc =
        rmap_crc_calculate(packet.data(), header_size);
    EXPECT_EQ(calculated_including_received_header_crc, 0);

    const uint8_t received_data_crc = packet.back();
    const uint8_t calculated_excluding_received_data_crc = rmap_crc_calculate(
        packet.data() + header_size,
        packet.size() - header_size - 1);
    EXPECT_EQ(calculated_excluding_received_data_crc, received_data_crc);

    const uint8_t calculated_including_received_data_crc = rmap_crc_calculate(
        packet.data() + header_size,
        packet.size() - header_size);
    EXPECT_EQ(calculated_including_received_data_crc, 0);
}
