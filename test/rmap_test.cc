#include <gtest/gtest.h>
#include <gmock/gmock.h>

extern "C" {
#include "rmap.h"
}

/* RMAP test patterns from ECSS‐E‐ST‐50‐52C, 5 February 2010. */

static const uint8_t test_pattern0_unverified_incrementing_write_with_reply[] = {
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
  0x56
};

static const uint8_t test_pattern0_expected_write_reply[] = {
  /* Initiator Logical Address */
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
  0xED
};

static const uint8_t test_pattern1_incrementing_read[] = {
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
  0xC9
};

static const uint8_t test_pattern1_expected_read_reply[] = {
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
  0x56
};

static const size_t test_pattern2_target_address_length = 7;
static const size_t test_pattern2_reply_address_length_padded = 8;
static const uint8_t test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses[] = {
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
  0xB4
};

static const size_t test_pattern2_reply_address_length = 7;
static const uint8_t test_pattern2_expected_write_reply_with_spacewire_addresses[] = {
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
  0x1D
};

static const size_t test_pattern3_target_address_length = 4;
static const uint8_t test_pattern3_incrementing_read_with_spacewire_addresses[] = {
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
  0xF7
};

static const size_t test_pattern3_reply_address_length = 4;
static const uint8_t test_pattern3_expected_read_reply_with_spacewire_addresses[] = {
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
  0xB4
};

typedef std::tuple<uint8_t (*)(const void *), uint8_t>
AccessorByteCheckParameters;
typedef std::tuple<const uint8_t *, AccessorByteCheckParameters>
PatternAccessorByteCheckParameters;

class AccessorByteCheckInPattern :
  public testing::TestWithParam<PatternAccessorByteCheckParameters>
{
};

TEST_P(AccessorByteCheckInPattern, Check)
{
  auto pattern = std::get<0>(GetParam());
  auto accessor = std::get<0>(std::get<1>(GetParam()));
  auto expected = std::get<1>(std::get<1>(GetParam()));

  EXPECT_EQ(accessor(pattern), expected);
}

INSTANTIATE_TEST_CASE_P(
    TestPattern0AccessorByteChecks,
    AccessorByteCheckInPattern,
    testing::Combine(
      testing::Values(test_pattern0_unverified_incrementing_write_with_reply),
      testing::Values(
        std::make_tuple(rmap_get_protocol, 1),
        std::make_tuple(
          rmap_get_instruction,
          1 << RMAP_INSTRUCTION_PACKET_TYPE_SHIFT |
          1 << RMAP_INSTRUCTION_COMMAND_INCREMENT_SHIFT |
          1 << RMAP_INSTRUCTION_COMMAND_WRITE_SHIFT |
          1 << RMAP_INSTRUCTION_COMMAND_REPLY_SHIFT),
        std::make_tuple(rmap_get_key, 0),
        std::make_tuple(rmap_get_target_logical_address, 0xFE),
        std::make_tuple(rmap_get_initiator_logical_address, 0x67),
        std::make_tuple(rmap_get_extended_address, 0x00))));

INSTANTIATE_TEST_CASE_P(
    TestPattern0ReplyAccessorByteChecks,
    AccessorByteCheckInPattern,
    testing::Combine(
      testing::Values(test_pattern0_expected_write_reply),
      testing::Values(
        std::make_tuple(rmap_get_protocol, 1),
        std::make_tuple(
          rmap_get_instruction,
          0 << RMAP_INSTRUCTION_PACKET_TYPE_SHIFT |
          1 << RMAP_INSTRUCTION_COMMAND_INCREMENT_SHIFT |
          1 << RMAP_INSTRUCTION_COMMAND_WRITE_SHIFT |
          1 << RMAP_INSTRUCTION_COMMAND_REPLY_SHIFT),
        std::make_tuple(rmap_get_status, RMAP_STATUS_FIELD_CODE_SUCCESS),
        std::make_tuple(rmap_get_target_logical_address, 0xFE),
        std::make_tuple(rmap_get_initiator_logical_address, 0x67))));

INSTANTIATE_TEST_CASE_P(
    TestPattern1AccessorByteChecks,
    AccessorByteCheckInPattern,
    testing::Combine(
      testing::Values(test_pattern1_incrementing_read),
      testing::Values(
        std::make_tuple(rmap_get_protocol, 1),
        std::make_tuple(
          rmap_get_instruction,
          1 << RMAP_INSTRUCTION_PACKET_TYPE_SHIFT |
          1 << RMAP_INSTRUCTION_COMMAND_INCREMENT_SHIFT |
          1 << RMAP_INSTRUCTION_COMMAND_REPLY_SHIFT),
        std::make_tuple(rmap_get_key, 0),
        std::make_tuple(rmap_get_target_logical_address, 0xFE),
        std::make_tuple(rmap_get_initiator_logical_address, 0x67),
        std::make_tuple(rmap_get_extended_address, 0x00))));

INSTANTIATE_TEST_CASE_P(
    TestPattern1ReplyAccessorByteChecks,
    AccessorByteCheckInPattern,
    testing::Combine(
      testing::Values(test_pattern1_expected_read_reply),
      testing::Values(
        std::make_tuple(rmap_get_protocol, 1),
        std::make_tuple(
          rmap_get_instruction,
          0 << RMAP_INSTRUCTION_PACKET_TYPE_SHIFT |
          1 << RMAP_INSTRUCTION_COMMAND_INCREMENT_SHIFT |
          1 << RMAP_INSTRUCTION_COMMAND_REPLY_SHIFT),
        std::make_tuple(rmap_get_status, RMAP_STATUS_FIELD_CODE_SUCCESS),
        std::make_tuple(rmap_get_target_logical_address, 0xFE),
        std::make_tuple(rmap_get_initiator_logical_address, 0x67))));

INSTANTIATE_TEST_CASE_P(
    TestPattern2AccessorByteChecks,
    AccessorByteCheckInPattern,
    testing::Combine(
      testing::Values(
        test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses +
        test_pattern2_target_address_length),
      testing::Values(
        std::make_tuple(rmap_get_protocol, 1),
        std::make_tuple(
          rmap_get_instruction,
          1 << RMAP_INSTRUCTION_PACKET_TYPE_SHIFT |
          1 << RMAP_INSTRUCTION_COMMAND_INCREMENT_SHIFT |
          1 << RMAP_INSTRUCTION_COMMAND_WRITE_SHIFT |
          1 << RMAP_INSTRUCTION_COMMAND_REPLY_SHIFT |
          (test_pattern2_reply_address_length_padded / 4) <<
          RMAP_INSTRUCTION_REPLY_ADDRESS_LENGTH_SHIFT),
        std::make_tuple(rmap_get_key, 0),
        std::make_tuple(rmap_get_target_logical_address, 0xFE),
        std::make_tuple(rmap_get_initiator_logical_address, 0x67),
        std::make_tuple(rmap_get_extended_address, 0x00))));

INSTANTIATE_TEST_CASE_P(
    TestPattern2ReplyAccessorByteChecks,
    AccessorByteCheckInPattern,
    testing::Combine(
      testing::Values(
        test_pattern2_expected_write_reply_with_spacewire_addresses +
        test_pattern2_reply_address_length),
      testing::Values(
        std::make_tuple(rmap_get_protocol, 1),
        std::make_tuple(
          rmap_get_instruction,
          0 << RMAP_INSTRUCTION_PACKET_TYPE_SHIFT |
          1 << RMAP_INSTRUCTION_COMMAND_INCREMENT_SHIFT |
          1 << RMAP_INSTRUCTION_COMMAND_WRITE_SHIFT |
          1 << RMAP_INSTRUCTION_COMMAND_REPLY_SHIFT |
          (test_pattern2_reply_address_length_padded / 4) <<
          RMAP_INSTRUCTION_REPLY_ADDRESS_LENGTH_SHIFT),
        std::make_tuple(rmap_get_status, RMAP_STATUS_FIELD_CODE_SUCCESS),
        std::make_tuple(rmap_get_target_logical_address, 0xFE),
        std::make_tuple(rmap_get_initiator_logical_address, 0x67))));

INSTANTIATE_TEST_CASE_P(
    TestPattern3AccessorByteChecks,
    AccessorByteCheckInPattern,
    testing::Combine(
      testing::Values(
        test_pattern3_incrementing_read_with_spacewire_addresses +
        test_pattern3_target_address_length),
      testing::Values(
        std::make_tuple(rmap_get_protocol, 1),
        std::make_tuple(
          rmap_get_instruction,
          1 << RMAP_INSTRUCTION_PACKET_TYPE_SHIFT |
          1 << RMAP_INSTRUCTION_COMMAND_INCREMENT_SHIFT |
          1 << RMAP_INSTRUCTION_COMMAND_REPLY_SHIFT |
          (test_pattern3_reply_address_length / 4) <<
          RMAP_INSTRUCTION_REPLY_ADDRESS_LENGTH_SHIFT),
        std::make_tuple(rmap_get_key, 0),
        std::make_tuple(rmap_get_target_logical_address, 0xFE),
        std::make_tuple(rmap_get_initiator_logical_address, 0x67),
        std::make_tuple(rmap_get_extended_address, 0x00))));

INSTANTIATE_TEST_CASE_P(
    TestPattern3ReplyAccessorByteChecks,
    AccessorByteCheckInPattern,
    testing::Combine(
      testing::Values(
        test_pattern3_expected_read_reply_with_spacewire_addresses +
        test_pattern3_reply_address_length),
      testing::Values(
        std::make_tuple(rmap_get_protocol, 1),
        std::make_tuple(
          rmap_get_instruction,
          0 << RMAP_INSTRUCTION_PACKET_TYPE_SHIFT |
          1 << RMAP_INSTRUCTION_COMMAND_INCREMENT_SHIFT |
          1 << RMAP_INSTRUCTION_COMMAND_REPLY_SHIFT |
          (test_pattern3_reply_address_length / 4) <<
          RMAP_INSTRUCTION_REPLY_ADDRESS_LENGTH_SHIFT),
        std::make_tuple(rmap_get_status, RMAP_STATUS_FIELD_CODE_SUCCESS),
        std::make_tuple(rmap_get_target_logical_address, 0xFE),
        std::make_tuple(rmap_get_initiator_logical_address, 0x67))));

static uint8_t patterns_with_non_rmap_protocols[][RMAP_HEADER_MINIMUM_SIZE] = {
  { 13, 0, 17 },
  { 13, 2, 17 },
  { 13, 123, 17 },
  { 13, 0xFF, 17 }
};
INSTANTIATE_TEST_CASE_P(
    NonRmapPatterns,
    AccessorByteCheckInPattern,
    testing::Values(
      std::make_tuple(
        patterns_with_non_rmap_protocols[0],
        std::make_tuple(rmap_get_protocol, 0)),
      std::make_tuple(
        patterns_with_non_rmap_protocols[1],
        std::make_tuple(rmap_get_protocol, 2)),
      std::make_tuple(
        patterns_with_non_rmap_protocols[2],
        std::make_tuple(rmap_get_protocol, 123)),
      std::make_tuple(
        patterns_with_non_rmap_protocols[3],
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

typedef std::tuple<std::tuple<rmap_packet_type_t, int, size_t>,
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

INSTANTIATE_TEST_CASE_P(
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

INSTANTIATE_TEST_CASE_P(
    CommandsAndRepliesWithReply,
    AccessorByteSetGet,
    testing::Combine(
      testing::Combine(
        testing::Values(RMAP_PACKET_TYPE_COMMAND, RMAP_PACKET_TYPE_REPLY),
        testing::Values(
          RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
          RMAP_COMMAND_CODE_REPLY),
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

  rmap_set_instruction(
      buf,
      RMAP_INSTRUCTION_PACKET_TYPE_MASK |
      RMAP_INSTRUCTION_COMMAND_CODE_MASK |
      RMAP_INSTRUCTION_REPLY_ADDRESS_LENGTH_MASK);
  EXPECT_EQ(
      rmap_get_instruction(buf),
      RMAP_INSTRUCTION_PACKET_TYPE_MASK |
      RMAP_INSTRUCTION_COMMAND_CODE_MASK |
      RMAP_INSTRUCTION_REPLY_ADDRESS_LENGTH_MASK);
}

typedef std::tuple<bool (*)(const void *), bool> AccessorBoolCheckParameters;
typedef std::tuple<const uint8_t *, AccessorBoolCheckParameters>
PatternAccessorBoolCheckParameters;

class AccessorBoolCheckInPattern :
  public testing::TestWithParam<PatternAccessorBoolCheckParameters>
{
};

TEST_P(AccessorBoolCheckInPattern, Check)
{
  auto pattern = std::get<0>(GetParam());
  auto accessor = std::get<0>(std::get<1>(GetParam()));
  auto expected = std::get<1>(std::get<1>(GetParam()));

  EXPECT_EQ(accessor(pattern), expected);
}

INSTANTIATE_TEST_CASE_P(
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
        std::make_tuple(rmap_is_unused_command_code, false))));

INSTANTIATE_TEST_CASE_P(
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
        std::make_tuple(rmap_is_unused_command_code, false))));

INSTANTIATE_TEST_CASE_P(
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
        std::make_tuple(rmap_is_unused_command_code, false))));

INSTANTIATE_TEST_CASE_P(
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
        std::make_tuple(rmap_is_unused_command_code, false))));

TEST(RmapIsUnusedPacketType, UnusedPacketType)
{
  uint8_t instruction;

  uint8_t pattern[
    sizeof(test_pattern0_unverified_incrementing_write_with_reply)];
  uint8_t pattern_reply[sizeof(test_pattern0_expected_write_reply)];

  memcpy(
      pattern,
      test_pattern0_unverified_incrementing_write_with_reply,
      sizeof(test_pattern0_unverified_incrementing_write_with_reply));

  memcpy(
      pattern_reply,
      test_pattern0_expected_write_reply,
      sizeof(test_pattern0_expected_write_reply));

  EXPECT_EQ(rmap_is_unused_packet_type(pattern), false);
  EXPECT_EQ(rmap_is_unused_packet_type(pattern_reply), false);

  instruction = rmap_get_instruction(pattern);
  rmap_set_instruction(pattern, instruction | 1 << 7);
  EXPECT_EQ(rmap_is_unused_packet_type(pattern), true);

  instruction = rmap_get_instruction(pattern_reply);
  rmap_set_instruction(pattern_reply, instruction | 1 << 7);
  EXPECT_EQ(rmap_is_unused_packet_type(pattern_reply), true);
}

TEST(RmapIsUnusedCommandCode, UnusedCommandCodes)
{
  uint8_t pattern[
    sizeof(test_pattern0_unverified_incrementing_write_with_reply)];

  memcpy(
      pattern,
      test_pattern0_unverified_incrementing_write_with_reply,
      sizeof(test_pattern0_unverified_incrementing_write_with_reply));

  EXPECT_EQ(rmap_is_unused_command_code(pattern), false);

  rmap_set_instruction(pattern, 1 << 6 | 0x0 << 2);
  EXPECT_EQ(rmap_is_unused_command_code(pattern), true);

  rmap_set_instruction(pattern, 1 << 6 | 0x1 << 2);
  EXPECT_EQ(rmap_is_unused_command_code(pattern), true);

  rmap_set_instruction(pattern, 1 << 6 | 0x4 << 2);
  EXPECT_EQ(rmap_is_unused_command_code(pattern), true);

  rmap_set_instruction(pattern, 1 << 6 | 0x5 << 2);
  EXPECT_EQ(rmap_is_unused_command_code(pattern), true);

  rmap_set_instruction(pattern, 1 << 6 | 0x6 << 2);
  EXPECT_EQ(rmap_is_unused_command_code(pattern), true);
}

TEST(RmapGetReplyAddress, Patterns)
{
  uint8_t reply_address[RMAP_REPLY_ADDRESS_LENGTH_MAX];
  size_t reply_address_size;

  EXPECT_EQ(
      rmap_get_reply_address(
        reply_address,
        &reply_address_size,
        sizeof(reply_address),
        test_pattern0_unverified_incrementing_write_with_reply),
      RMAP_OK);
  EXPECT_EQ(reply_address_size, 0);

  EXPECT_EQ(
      rmap_get_reply_address(
        reply_address,
        &reply_address_size,
        sizeof(reply_address),
        test_pattern1_incrementing_read),
      RMAP_OK);
  EXPECT_EQ(reply_address_size, 0);

  EXPECT_EQ(
      rmap_get_reply_address(
        reply_address,
        &reply_address_size,
        sizeof(reply_address),
        test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses +
        test_pattern2_target_address_length),
      RMAP_OK);
  EXPECT_EQ(reply_address_size, test_pattern2_reply_address_length);
  EXPECT_EQ(
      std::vector<uint8_t>(reply_address, reply_address + reply_address_size),
      std::vector<uint8_t>(
        test_pattern2_expected_write_reply_with_spacewire_addresses,
        test_pattern2_expected_write_reply_with_spacewire_addresses +
        test_pattern2_reply_address_length));

  EXPECT_EQ(
      rmap_get_reply_address(
        reply_address,
        &reply_address_size,
        sizeof(reply_address),
        test_pattern3_incrementing_read_with_spacewire_addresses +
        test_pattern3_target_address_length),
      RMAP_OK);
  EXPECT_EQ(reply_address_size, test_pattern3_reply_address_length);
  EXPECT_EQ(
      std::vector<uint8_t>(reply_address, reply_address + reply_address_size),
      std::vector<uint8_t>(
        test_pattern3_expected_read_reply_with_spacewire_addresses,
        test_pattern3_expected_read_reply_with_spacewire_addresses +
        test_pattern3_reply_address_length));
}

typedef std::tuple<std::vector<uint8_t>, std::vector<uint8_t>>
SetReplyAddressParameters;

class SetReplyAddress :
  public testing::TestWithParam<SetReplyAddressParameters>
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

INSTANTIATE_TEST_CASE_P(
    ReplyAddressPatterns,
    SetReplyAddress,
    testing::Values(
      std::make_tuple(
        std::vector<uint8_t>({ 1 }),
        std::vector<uint8_t>({ 0, 0, 0, 1 })),
      std::make_tuple(
        std::vector<uint8_t>({ 1, 0 }),
        std::vector<uint8_t>({ 0, 0, 1, 0 })),
      std::make_tuple(
        std::vector<uint8_t>({ 1, 2, 3 }),
        std::vector<uint8_t>({ 0, 1, 2, 3 })),
      std::make_tuple(
        std::vector<uint8_t>({ 1, 0, 0, 0 }),
        std::vector<uint8_t>({ 1, 0, 0, 0 })),
      std::make_tuple(
        std::vector<uint8_t>({ 1, 2, 3, 4 }),
        std::vector<uint8_t>({ 1, 2, 3, 4 })),
      std::make_tuple(
        std::vector<uint8_t>({ 1, 2, 3, 4, 5 }),
        std::vector<uint8_t>({ 0, 0, 0, 1, 2, 3, 4, 5 })),
      std::make_tuple(
        std::vector<uint8_t>({ 1, 2, 3, 4, 5, 6, 7 }),
        std::vector<uint8_t>({ 0, 1, 2, 3, 4, 5, 6, 7 })),
      std::make_tuple(
        std::vector<uint8_t>({ 1, 2, 3, 4, 5, 6, 7, 8 }),
        std::vector<uint8_t>({ 1, 2, 3, 4, 5, 6, 7, 8 })),
      std::make_tuple(
        std::vector<uint8_t>({ 1, 2, 3, 4, 5, 6, 7, 8, 9 }),
        std::vector<uint8_t>({ 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 })),
      std::make_tuple(
        std::vector<uint8_t>({ 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 }),
        std::vector<uint8_t>({ 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 })),
      std::make_tuple(
        std::vector<uint8_t>({ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 }),
        std::vector<uint8_t>({ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 })),
      std::make_tuple(
        std::vector<uint8_t>({ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }),
        std::vector<uint8_t>({ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 })),
      std::make_tuple(
        std::vector<uint8_t>({ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 }),
        std::vector<uint8_t>({ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 }))));

TEST(RmapGetTransationIdentifier, Patterns)
{
  EXPECT_EQ(
      rmap_get_transaction_identifier(
        test_pattern0_unverified_incrementing_write_with_reply),
      0x0000);

  EXPECT_EQ(
      rmap_get_transaction_identifier(test_pattern0_expected_write_reply),
      0x0000);

  EXPECT_EQ(
      rmap_get_transaction_identifier(test_pattern1_incrementing_read),
      0x0001);

  EXPECT_EQ(
      rmap_get_transaction_identifier(test_pattern1_expected_read_reply),
      0x0001);

  EXPECT_EQ(
      rmap_get_transaction_identifier(
        test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses +
        test_pattern2_target_address_length),
      0x0002);

  EXPECT_EQ(
      rmap_get_transaction_identifier(
        test_pattern2_expected_write_reply_with_spacewire_addresses +
        test_pattern2_reply_address_length),
      0x0002);

  EXPECT_EQ(
      rmap_get_transaction_identifier(
        test_pattern3_incrementing_read_with_spacewire_addresses +
        test_pattern3_target_address_length),
      0x0003);

  EXPECT_EQ(
      rmap_get_transaction_identifier(
        test_pattern3_expected_read_reply_with_spacewire_addresses +
        test_pattern3_reply_address_length),
      0x0003);
}

typedef std::tuple<rmap_packet_type_t, int, size_t> SetTransactionIdentifierParameters;

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

INSTANTIATE_TEST_CASE_P(
    WriteWithoutReply,
    SetTransactionIdentifier,
    testing::Values(
      std::make_tuple(
        RMAP_PACKET_TYPE_COMMAND,
        RMAP_COMMAND_CODE_WRITE,
        0)));

INSTANTIATE_TEST_CASE_P(
    CommandsAndRepliesWithReply,
    SetTransactionIdentifier,
    testing::Combine(
      testing::Values(RMAP_PACKET_TYPE_COMMAND, RMAP_PACKET_TYPE_REPLY),
      testing::Values(
        RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
        RMAP_COMMAND_CODE_REPLY),
      testing::Range((size_t)0, (size_t)(RMAP_REPLY_ADDRESS_LENGTH_MAX + 1))));

TEST(RmapGetAddress, Patterns)
{
  EXPECT_EQ(
      rmap_get_address(
        test_pattern0_unverified_incrementing_write_with_reply),
      0xA0000000);

  EXPECT_EQ(
      rmap_get_address(test_pattern1_incrementing_read),
      0xA0000000);

  EXPECT_EQ(
      rmap_get_address(
        test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses +
        test_pattern2_target_address_length),
      0xA0000010);

  EXPECT_EQ(
      rmap_get_address(
        test_pattern3_incrementing_read_with_spacewire_addresses +
        test_pattern3_target_address_length),
      0xA0000010);
}

typedef std::tuple<rmap_packet_type_t, int, size_t> SetAddressParameters;

class SetAddress :
  public testing::TestWithParam<SetAddressParameters>
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

INSTANTIATE_TEST_CASE_P(
    WriteWithoutReply,
    SetAddress,
    testing::Values(
      std::make_tuple(
        RMAP_PACKET_TYPE_COMMAND,
        RMAP_COMMAND_CODE_WRITE,
        0)));

INSTANTIATE_TEST_CASE_P(
    CommandsWithReply,
    SetAddress,
    testing::Combine(
      testing::Values(RMAP_PACKET_TYPE_COMMAND),
      testing::Values(
        RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
        RMAP_COMMAND_CODE_REPLY),
      testing::Range((size_t)0, (size_t)(RMAP_REPLY_ADDRESS_LENGTH_MAX + 1))));

TEST(RmapGetHeaderDataLength, Patterns)
{
  EXPECT_EQ(
      rmap_get_data_length(
        test_pattern0_unverified_incrementing_write_with_reply),
      0x00000010);

  EXPECT_EQ(
      rmap_get_data_length(test_pattern1_incrementing_read),
      0x00000010);

  EXPECT_EQ(
      rmap_get_data_length(test_pattern1_expected_read_reply),
      0x00000010);

  EXPECT_EQ(
      rmap_get_data_length(
        test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses +
        test_pattern2_target_address_length),
      0x00000010);

  EXPECT_EQ(
      rmap_get_data_length(
        test_pattern3_incrementing_read_with_spacewire_addresses +
        test_pattern3_target_address_length),
      0x00000010);

  EXPECT_EQ(
      rmap_get_data_length(
        test_pattern3_expected_read_reply_with_spacewire_addresses +
        test_pattern3_reply_address_length),
      0x00000010);
}

typedef std::tuple<rmap_packet_type_t, int, size_t> SetDataLengthParameters;

class SetDataLength :
  public testing::TestWithParam<SetDataLengthParameters>
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

INSTANTIATE_TEST_CASE_P(
    WriteWithoutReply,
    SetDataLength,
    testing::Values(
      std::make_tuple(
        RMAP_PACKET_TYPE_COMMAND,
        RMAP_COMMAND_CODE_WRITE,
        0)));

INSTANTIATE_TEST_CASE_P(
    WriteWithReply,
    SetDataLength,
    testing::Combine(
      testing::Values(RMAP_PACKET_TYPE_COMMAND),
      testing::Values(RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY),
      testing::Range((size_t)0, (size_t)(RMAP_REPLY_ADDRESS_LENGTH_MAX + 1))));

INSTANTIATE_TEST_CASE_P(
    ReadReply,
    SetDataLength,
    testing::Combine(
      testing::Values(RMAP_PACKET_TYPE_REPLY),
      testing::Values(RMAP_COMMAND_CODE_REPLY),
      testing::Range((size_t)0, (size_t)(RMAP_REPLY_ADDRESS_LENGTH_MAX + 1))));

TEST(RmapCalculateHeaderSize, Patterns)
{
  EXPECT_EQ(
      rmap_calculate_header_size(
        test_pattern0_unverified_incrementing_write_with_reply),
      RMAP_COMMAND_HEADER_STATIC_SIZE);

  EXPECT_EQ(
      rmap_calculate_header_size(test_pattern0_expected_write_reply),
      RMAP_WRITE_REPLY_HEADER_STATIC_SIZE);

  EXPECT_EQ(
      rmap_calculate_header_size(test_pattern1_incrementing_read),
      RMAP_COMMAND_HEADER_STATIC_SIZE);

  EXPECT_EQ(
      rmap_calculate_header_size(test_pattern1_expected_read_reply),
      RMAP_READ_REPLY_HEADER_STATIC_SIZE);

  EXPECT_EQ(
      rmap_calculate_header_size(
        test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses +
        test_pattern2_target_address_length),
      RMAP_COMMAND_HEADER_STATIC_SIZE +
      test_pattern2_reply_address_length_padded);

  EXPECT_EQ(
      rmap_calculate_header_size(
        test_pattern2_expected_write_reply_with_spacewire_addresses +
        test_pattern2_reply_address_length),
      RMAP_WRITE_REPLY_HEADER_STATIC_SIZE);

  EXPECT_EQ(
      rmap_calculate_header_size(
        test_pattern3_incrementing_read_with_spacewire_addresses +
        test_pattern3_target_address_length),
      RMAP_COMMAND_HEADER_STATIC_SIZE + test_pattern3_reply_address_length);

  EXPECT_EQ(
      rmap_calculate_header_size(
        test_pattern3_expected_read_reply_with_spacewire_addresses +
        test_pattern3_reply_address_length),
      RMAP_READ_REPLY_HEADER_STATIC_SIZE);
}

typedef std::tuple<rmap_packet_type_t, int, std::tuple<size_t, size_t>>
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

INSTANTIATE_TEST_CASE_P(
    Command,
    CalculateHeaderSize,
    testing::Combine(
      testing::Values(RMAP_PACKET_TYPE_COMMAND),
      testing::Values(
        RMAP_COMMAND_CODE_WRITE,
        RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
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

INSTANTIATE_TEST_CASE_P(
    WriteReply,
    CalculateHeaderSize,
    testing::Combine(
      testing::Values(RMAP_PACKET_TYPE_REPLY),
      testing::Values(RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY),
      testing::Combine(
        testing::Range((size_t)0, (size_t)RMAP_REPLY_ADDRESS_LENGTH_MAX + 1),
        testing::Values(RMAP_WRITE_REPLY_HEADER_STATIC_SIZE))));

INSTANTIATE_TEST_CASE_P(
    ReadReply,
    CalculateHeaderSize,
    testing::Combine(
      testing::Values(RMAP_PACKET_TYPE_REPLY),
      testing::Values(RMAP_COMMAND_CODE_REPLY),
      testing::Combine(
        testing::Range((size_t)0, (size_t)RMAP_REPLY_ADDRESS_LENGTH_MAX + 1),
        testing::Values(RMAP_READ_REPLY_HEADER_STATIC_SIZE))));

typedef std::tuple<const uint8_t *, size_t> PatternParameters;

class AllTestPatterns : public testing::TestWithParam<PatternParameters>
{
};

TEST_P(AllTestPatterns, RmapCalculateAndSetHeaderCrcPatternsShouldNotChange)
{
  auto pattern = std::get<0>(GetParam());
  auto pattern_size = std::get<1>(GetParam());

  std::vector<uint8_t> packet(pattern, pattern + pattern_size);
  const auto expected_packet = packet;
  /* CRC is corrupted first, to make sure that an implementation that does
   * nothing cannot pass the test.
   */
  packet[rmap_calculate_header_size(packet.data()) - 1] ^= 0xFF;
  rmap_calculate_and_set_header_crc(packet.data());
  EXPECT_EQ(packet, expected_packet);
}

TEST_P(AllTestPatterns, VerifyHeaderIntegrityOk)
{
  auto pattern = std::get<0>(GetParam());
  auto pattern_size = std::get<1>(GetParam());

  EXPECT_EQ(rmap_verify_header_integrity(pattern, pattern_size), RMAP_OK);
}

TEST_P(AllTestPatterns, VerifyHeaderIntegrityNoRmapProtocol)
{
  uint8_t protocol;

  auto pattern = std::get<0>(GetParam());
  auto pattern_size = std::get<1>(GetParam());

  std::vector<uint8_t> packet(pattern, pattern + pattern_size);

  /* Set all non-RMAP protocol values. */
  for (protocol = 0; protocol < 0xFF; ++protocol) {
    if (protocol == 1) {
      /* Valid, skip. */
      continue;
    }
    packet[1] = protocol;
    rmap_calculate_and_set_header_crc(packet.data());
    EXPECT_EQ(
        rmap_verify_header_integrity(packet.data(), packet.size()),
        RMAP_NO_RMAP_PROTOCOL);
  }
}

TEST_P(AllTestPatterns, VerifyHeaderIntegrityCrcErrorFromCorruptKeyOrStatus)
{
  unsigned int i;

  auto pattern = std::get<0>(GetParam());
  auto pattern_size = std::get<1>(GetParam());

  std::vector<uint8_t> packet(pattern, pattern + pattern_size);

  /* Flip one or more bits in the key field in commands or in the status field
   * in replies.
   */
  const size_t corrupt_offset = 3;
  for (i = 1; i < 0xFF; ++i) {
    packet[corrupt_offset] = pattern[corrupt_offset] ^ i;
    EXPECT_EQ(
        rmap_verify_header_integrity(packet.data(), packet.size()),
        RMAP_HEADER_CRC_ERROR);
  }
}

TEST_P(AllTestPatterns, VerifyHeaderIntegrityCrcErrorFromCorruptCrcField)
{
  unsigned int i;

  auto pattern = std::get<0>(GetParam());
  auto pattern_size = std::get<1>(GetParam());

  std::vector<uint8_t> packet(pattern, pattern + pattern_size);

  /* Flip one or more bits in the CRC field. */
  const size_t corrupt_offset = rmap_calculate_header_size(packet.data()) - 1;
  for (i = 1; i < 0xFF; ++i) {
    packet[corrupt_offset] = pattern[corrupt_offset] ^ i;
    EXPECT_EQ(
        rmap_verify_header_integrity(packet.data(), packet.size()),
        RMAP_HEADER_CRC_ERROR);
  }
}

TEST_P(AllTestPatterns, VerifyHeaderIntegrityIncompleteHeader)
{
  size_t incomplete_header_size;

  auto pattern = std::get<0>(GetParam());

  const rmap_status_t expected_status = RMAP_INCOMPLETE_HEADER;

  incomplete_header_size = 0;
  EXPECT_EQ(
      rmap_verify_header_integrity(pattern, incomplete_header_size),
      expected_status);

  incomplete_header_size = 1;
  EXPECT_EQ(
      rmap_verify_header_integrity(pattern, incomplete_header_size),
      expected_status);

  incomplete_header_size = RMAP_HEADER_MINIMUM_SIZE - 1;
  EXPECT_EQ(
      rmap_verify_header_integrity(pattern, incomplete_header_size),
      expected_status);

  incomplete_header_size = rmap_calculate_header_size(pattern) - 1;
  EXPECT_EQ(
      rmap_verify_header_integrity(pattern, incomplete_header_size),
      expected_status);
}

TEST_P(AllTestPatterns, VerifyHeaderIntegrityCompleteHeaderOnly)
{
  auto pattern = std::get<0>(GetParam());

  EXPECT_EQ(
      rmap_verify_header_integrity(
        pattern,
        rmap_calculate_header_size(pattern)),
      RMAP_OK);
}

TEST_P(AllTestPatterns, VerifyHeaderInstructionOk)
{
  auto pattern = std::get<0>(GetParam());

  EXPECT_EQ(rmap_verify_header_instruction(pattern), RMAP_OK);
}

TEST_P(AllTestPatterns, RmapInitializeHeaderPatternsShouldNotChange)
{
  rmap_packet_type_t packet_type;
  int command_code;
  uint8_t reply_address[RMAP_REPLY_ADDRESS_LENGTH_MAX];
  size_t reply_address_unpadded_size;
  size_t header_offset;

  auto pattern = std::get<0>(GetParam());
  auto pattern_size = std::get<1>(GetParam());

  std::vector<uint8_t> packet(pattern, pattern + pattern_size);

  packet_type = RMAP_PACKET_TYPE_COMMAND;
  if (!rmap_is_command(pattern)) {
    packet_type = RMAP_PACKET_TYPE_REPLY;
  }

  command_code = 0;
  if (rmap_is_write(pattern)) {
    command_code |= RMAP_COMMAND_CODE_WRITE;
  }
  if (rmap_is_verify_data_before_write(pattern)) {
    command_code |= RMAP_COMMAND_CODE_VERIFY;
  }
  if (rmap_is_with_reply(pattern)) {
    command_code |= RMAP_COMMAND_CODE_REPLY;
  }
  if (rmap_is_increment_address(pattern)) {
    command_code |= RMAP_COMMAND_CODE_INCREMENT;
  }

  const rmap_status_t status = rmap_get_reply_address(
      reply_address,
      &reply_address_unpadded_size,
      sizeof(reply_address),
      pattern);
  ASSERT_EQ(status, RMAP_OK);

  const auto expected_packet = packet;
  /* Protocol identifier and instruction is corrupted first, to make sure that
   * an implementation that does nothing cannot pass the test.
   */
  packet[1] ^= 0xFF;
  packet[2] ^= 0xFF;
  const auto corrupted_packet = packet;

  EXPECT_EQ(
      rmap_initialize_header(
        packet.data(),
        packet.size(),
        packet_type,
        command_code,
        reply_address_unpadded_size),
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
        rmap_calculate_header_size(pattern),
        packet_type,
        command_code,
        reply_address_unpadded_size),
      RMAP_OK);
  EXPECT_EQ(packet, expected_packet);
  EXPECT_EQ(header_offset, 0);
}

INSTANTIATE_TEST_CASE_P(
    AllPatterns,
    AllTestPatterns,
    testing::Values(
      std::make_tuple(
        test_pattern0_unverified_incrementing_write_with_reply,
        sizeof(test_pattern0_unverified_incrementing_write_with_reply)),
      std::make_tuple(
        test_pattern0_expected_write_reply,
        sizeof(test_pattern0_expected_write_reply)),
      std::make_tuple(
        test_pattern1_incrementing_read,
        sizeof(test_pattern1_expected_read_reply)),
      std::make_tuple(
        test_pattern1_expected_read_reply,
        sizeof(test_pattern1_expected_read_reply)),
      std::make_tuple(
        test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses +
        test_pattern2_target_address_length,
        sizeof(test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses) -
        test_pattern2_target_address_length),
      std::make_tuple(
        test_pattern2_expected_write_reply_with_spacewire_addresses +
        test_pattern2_reply_address_length,
        sizeof(test_pattern2_expected_write_reply_with_spacewire_addresses) -
        test_pattern2_reply_address_length),
      std::make_tuple(
          test_pattern3_incrementing_read_with_spacewire_addresses +
          test_pattern3_target_address_length,
          sizeof(test_pattern3_incrementing_read_with_spacewire_addresses) -
          test_pattern3_target_address_length),
      std::make_tuple(
          test_pattern3_expected_read_reply_with_spacewire_addresses +
          test_pattern3_reply_address_length,
          sizeof(test_pattern3_expected_read_reply_with_spacewire_addresses) -
          test_pattern3_reply_address_length)));

class TestPatternsWithData : public testing::TestWithParam<PatternParameters>
{
};

TEST_P(TestPatternsWithData, VerifyDataCrcErrorFromCorruptData)
{
  unsigned int i;

  auto pattern = std::get<0>(GetParam());
  auto pattern_size = std::get<1>(GetParam());

  std::vector<uint8_t> packet(pattern, pattern + pattern_size);

  /* Flip one or more bits in the data byte immediately following the header.
   */
  const size_t corrupt_offset = rmap_calculate_header_size(packet.data());
  for (i = 1; i < 0xFF; ++i) {
    packet[corrupt_offset] = pattern[corrupt_offset] ^ i;
    EXPECT_EQ(
        rmap_verify_data(packet.data(), packet.size()),
        RMAP_INVALID_DATA_CRC);
  }
}

TEST_P(TestPatternsWithData, VerifyDataCrcErrorFromCorruptCrcField)
{
  unsigned int i;

  auto pattern = std::get<0>(GetParam());
  auto pattern_size = std::get<1>(GetParam());

  std::vector<uint8_t> packet(pattern, pattern + pattern_size);

  /* Flip one or more bits in the CRC field. */
  const size_t corrupt_offset =
    rmap_calculate_header_size(packet.data()) +
    rmap_get_data_length(packet.data());
  for (i = 1; i < 0xFF; ++i) {
    packet[corrupt_offset] = pattern[corrupt_offset] ^ i;
    EXPECT_EQ(
        rmap_verify_data(packet.data(), packet.size()),
        RMAP_INVALID_DATA_CRC);
  }
}

TEST_P(TestPatternsWithData, VerifyDataIncompleteData)
{
  size_t incomplete_packet_size;

  auto pattern = std::get<0>(GetParam());
  auto pattern_size = std::get<1>(GetParam());

  const rmap_status_t expected_status = RMAP_INSUFFICIENT_DATA;

  incomplete_packet_size = rmap_calculate_header_size(pattern);
  EXPECT_EQ(
      rmap_verify_data(pattern, incomplete_packet_size),
      expected_status);

  incomplete_packet_size = rmap_calculate_header_size(pattern) + 1;
  EXPECT_EQ(
      rmap_verify_data(pattern, incomplete_packet_size),
      expected_status);

  incomplete_packet_size = pattern_size - 2;
  EXPECT_EQ(
      rmap_verify_data(pattern, incomplete_packet_size),
      expected_status);

  incomplete_packet_size = pattern_size - 1;
  EXPECT_EQ(
      rmap_verify_data(pattern, incomplete_packet_size),
      expected_status);
}

TEST_P(TestPatternsWithData, VerifyDataTooMuchData)
{
  size_t too_long_packet_size;

  auto pattern = std::get<0>(GetParam());
  auto pattern_size = std::get<1>(GetParam());

  std::vector<uint8_t> packet(pattern, pattern + pattern_size);

  packet.resize(RMAP_HEADER_SIZE_MAX + RMAP_DATA_LENGTH_MAX + 1);

  const rmap_status_t expected_status = RMAP_TOO_MUCH_DATA;

  too_long_packet_size = pattern_size + 1;
  EXPECT_EQ(
      rmap_verify_data(packet.data(), too_long_packet_size),
      expected_status);

  too_long_packet_size = pattern_size + 123;
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
  auto pattern = std::get<0>(GetParam());
  auto pattern_size = std::get<1>(GetParam());

  EXPECT_EQ(rmap_verify_data(pattern, pattern_size), RMAP_OK);
}

INSTANTIATE_TEST_CASE_P(
    PatternsWithData,
    TestPatternsWithData,
    testing::Values(
      std::make_tuple(
        test_pattern0_unverified_incrementing_write_with_reply,
        sizeof(test_pattern0_unverified_incrementing_write_with_reply)),
      std::make_tuple(
        test_pattern1_expected_read_reply,
        sizeof(test_pattern1_expected_read_reply)),
      std::make_tuple(
        test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses +
        test_pattern2_target_address_length,
        sizeof(test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses) -
        test_pattern2_target_address_length),
      std::make_tuple(
          test_pattern3_expected_read_reply_with_spacewire_addresses +
          test_pattern3_reply_address_length,
          sizeof(test_pattern3_expected_read_reply_with_spacewire_addresses) -
          test_pattern3_reply_address_length)));

typedef std::tuple<rmap_packet_type_t, int, size_t, rmap_status_t>
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

INSTANTIATE_TEST_CASE_P(
    ReservedPacketTypes,
    VerifyHeaderInstruction,
    testing::Combine(
      testing::Values(
        RMAP_PACKET_TYPE_COMMAND_RESERVED,
        RMAP_PACKET_TYPE_REPLY_RESERVED),
      testing::Range(
        0,
        (RMAP_COMMAND_CODE_WRITE |
         RMAP_COMMAND_CODE_VERIFY |
         RMAP_COMMAND_CODE_REPLY |
         RMAP_COMMAND_CODE_INCREMENT) + 1),
      testing::Range((size_t)0, (size_t)(RMAP_REPLY_ADDRESS_LENGTH_MAX + 1)),
      testing::Values(RMAP_UNUSED_PACKET_TYPE)));

INSTANTIATE_TEST_CASE_P(
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

INSTANTIATE_TEST_CASE_P(
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
        RMAP_COMMAND_CODE_WRITE |
        RMAP_COMMAND_CODE_VERIFY |
        RMAP_COMMAND_CODE_INCREMENT),
      testing::Range((size_t)0, (size_t)(RMAP_REPLY_ADDRESS_LENGTH_MAX + 1)),
      testing::Values(RMAP_NO_REPLY)));

INSTANTIATE_TEST_CASE_P(
    ReplyWithUnusedCommandCodes,
    VerifyHeaderInstruction,
    testing::Combine(
      testing::Values(RMAP_PACKET_TYPE_REPLY),
      testing::Values(RMAP_COMMAND_CODE_VERIFY | RMAP_COMMAND_CODE_REPLY),
      testing::Range((size_t)0, (size_t)(RMAP_REPLY_ADDRESS_LENGTH_MAX + 1)),
      testing::Values(RMAP_UNUSED_COMMAND_CODE)));

INSTANTIATE_TEST_CASE_P(
    ValidCommands,
    VerifyHeaderInstruction,
    testing::Combine(
      testing::Values(RMAP_PACKET_TYPE_COMMAND),
      testing::Values(
        RMAP_COMMAND_CODE_REPLY,
        RMAP_COMMAND_CODE_REPLY | RMAP_COMMAND_CODE_INCREMENT,
        RMAP_COMMAND_CODE_VERIFY |
        RMAP_COMMAND_CODE_REPLY |
        RMAP_COMMAND_CODE_INCREMENT,
        RMAP_COMMAND_CODE_WRITE,
        RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_INCREMENT,
        RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
        RMAP_COMMAND_CODE_WRITE |
        RMAP_COMMAND_CODE_REPLY |
        RMAP_COMMAND_CODE_INCREMENT,
        RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_VERIFY,
        RMAP_COMMAND_CODE_WRITE |
        RMAP_COMMAND_CODE_VERIFY |
        RMAP_COMMAND_CODE_INCREMENT,
        RMAP_COMMAND_CODE_WRITE |
        RMAP_COMMAND_CODE_VERIFY |
        RMAP_COMMAND_CODE_REPLY,
        RMAP_COMMAND_CODE_WRITE |
        RMAP_COMMAND_CODE_VERIFY |
        RMAP_COMMAND_CODE_REPLY |
        RMAP_COMMAND_CODE_INCREMENT),
      testing::Range((size_t)0, (size_t)(RMAP_REPLY_ADDRESS_LENGTH_MAX + 1)),
      testing::Values(RMAP_OK)));

INSTANTIATE_TEST_CASE_P(
    ValidReplies,
    VerifyHeaderInstruction,
    testing::Combine(
      testing::Values(RMAP_PACKET_TYPE_REPLY),
      testing::Values(
        RMAP_COMMAND_CODE_REPLY,
        RMAP_COMMAND_CODE_REPLY | RMAP_COMMAND_CODE_INCREMENT,
        RMAP_COMMAND_CODE_VERIFY |
        RMAP_COMMAND_CODE_REPLY |
        RMAP_COMMAND_CODE_INCREMENT,
        RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
        RMAP_COMMAND_CODE_WRITE |
        RMAP_COMMAND_CODE_REPLY |
        RMAP_COMMAND_CODE_INCREMENT,
        RMAP_COMMAND_CODE_WRITE |
        RMAP_COMMAND_CODE_VERIFY |
        RMAP_COMMAND_CODE_REPLY,
        RMAP_COMMAND_CODE_WRITE |
        RMAP_COMMAND_CODE_VERIFY |
        RMAP_COMMAND_CODE_REPLY |
        RMAP_COMMAND_CODE_INCREMENT),
      testing::Range((size_t)0, (size_t)(RMAP_REPLY_ADDRESS_LENGTH_MAX + 1)),
      testing::Values(RMAP_OK)));

typedef std::tuple<size_t, rmap_packet_type_t, int, size_t, rmap_status_t>
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

INSTANTIATE_TEST_CASE_P(
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

INSTANTIATE_TEST_CASE_P(
    InvalidPacketTypes,
    InitializeHeader,
    testing::Values(
      std::make_tuple(
        64,
        (rmap_packet_type_t)(RMAP_PACKET_TYPE_REPLY_RESERVED + 1),
        RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
        0,
        RMAP_INVALID_PACKET_TYPE),
      std::make_tuple(
        64,
        (rmap_packet_type_t)0xFF,
        RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
        0,
        RMAP_INVALID_PACKET_TYPE)));

INSTANTIATE_TEST_CASE_P(
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
        (RMAP_COMMAND_CODE_WRITE |
        RMAP_COMMAND_CODE_VERIFY |
        RMAP_COMMAND_CODE_INCREMENT |
        RMAP_COMMAND_CODE_REPLY) + 1,
        0,
        RMAP_INVALID_COMMAND_CODE),
      std::make_tuple(
        64,
        RMAP_PACKET_TYPE_COMMAND,
        0xFF,
        0,
        RMAP_INVALID_COMMAND_CODE)));

INSTANTIATE_TEST_CASE_P(
    NoReply,
    InitializeHeader,
    testing::Values(
      std::make_tuple(
        64,
        RMAP_PACKET_TYPE_REPLY,
        RMAP_COMMAND_CODE_WRITE,
        0,
        RMAP_OK)));

INSTANTIATE_TEST_CASE_P(
    UnusedCommandCodes,
    InitializeHeader,
    testing::Values(
      std::make_tuple(
        64,
        RMAP_PACKET_TYPE_COMMAND,
        0,
        0,
        RMAP_OK),
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

INSTANTIATE_TEST_CASE_P(
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
        RMAP_REPLY_ADDRESS_TOO_LONG)));

INSTANTIATE_TEST_CASE_P(
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

INSTANTIATE_TEST_CASE_P(
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

INSTANTIATE_TEST_CASE_P(
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

INSTANTIATE_TEST_CASE_P(
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

TEST(RmapRecreateHeader, TestPattern0Command)
{
  size_t header_offset;
  uint8_t buf[1234];

  std::vector<uint8_t> expected_packet(
      test_pattern0_unverified_incrementing_write_with_reply,
      test_pattern0_unverified_incrementing_write_with_reply +
      sizeof(test_pattern0_unverified_incrementing_write_with_reply));

  memset(buf, 0, sizeof(buf));

  const uint8_t data[] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
  };

  const size_t  data_offset = 123;

  memcpy(buf + data_offset, data, sizeof(data));

  EXPECT_EQ(
      rmap_initialize_header_before(
        &header_offset,
        buf,
        data_offset,
        RMAP_PACKET_TYPE_COMMAND,
        RMAP_COMMAND_CODE_WRITE |
        RMAP_COMMAND_CODE_REPLY |
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
  rmap_set_data_length(header, sizeof(data));

  rmap_calculate_and_set_header_crc(header);

  buf[data_offset + sizeof(data)] =
    rmap_crc_calculate(buf + data_offset, sizeof(data));

  std::vector<uint8_t> packet(
      buf + header_offset,
      buf + data_offset + sizeof(data) + 1);
  EXPECT_EQ(packet, expected_packet);
}

TEST(RmapRecreateHeader, TestPattern0Reply)
{
  uint8_t buf[123];

  std::vector<uint8_t> expected_packet(
      test_pattern0_expected_write_reply,
      test_pattern0_expected_write_reply +
      sizeof(test_pattern0_expected_write_reply));

  memset(buf, 0, sizeof(buf));

  EXPECT_EQ(
      rmap_initialize_header(
        buf,
        sizeof(buf),
        RMAP_PACKET_TYPE_REPLY,
        RMAP_COMMAND_CODE_WRITE |
        RMAP_COMMAND_CODE_REPLY |
        RMAP_COMMAND_CODE_INCREMENT,
        0),
      RMAP_OK);

  rmap_set_initiator_logical_address(buf, 0x67);
  rmap_set_status(buf, RMAP_STATUS_FIELD_CODE_SUCCESS);
  rmap_set_target_logical_address(buf, 0xFE);
  rmap_set_transaction_identifier(buf, 0);
  rmap_calculate_and_set_header_crc(buf);

  std::vector<uint8_t> packet(buf, buf + rmap_calculate_header_size(buf));
  EXPECT_EQ(packet, expected_packet);
}

TEST(RmapRecreateHeader, TestPattern1Command)
{
  uint8_t buf[123];

  std::vector<uint8_t> expected_packet(
      test_pattern1_incrementing_read,
      test_pattern1_incrementing_read +
      sizeof(test_pattern1_incrementing_read));

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

  std::vector<uint8_t> expected_packet(
      test_pattern1_expected_read_reply,
      test_pattern1_expected_read_reply +
      sizeof(test_pattern1_expected_read_reply));

  memset(buf, 0, sizeof(buf));

  const uint8_t data[] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
  };

  const size_t  data_offset = 123;

  memcpy(buf + data_offset, data, sizeof(data));

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
  rmap_set_data_length(header, sizeof(data));

  rmap_calculate_and_set_header_crc(header);

  buf[data_offset + sizeof(data)] =
    rmap_crc_calculate(buf + data_offset, sizeof(data));

  std::vector<uint8_t> packet(
      buf + header_offset,
      buf + data_offset + sizeof(data) + 1);
  EXPECT_EQ(packet, expected_packet);
}

TEST(RmapRecreateHeader, TestPattern2Command)
{
  size_t header_offset;
  uint8_t buf[1234];

  std::vector<uint8_t> expected_packet(
      test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses,
      test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses +
      sizeof(test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses));

  memset(buf, 0, sizeof(buf));

  const uint8_t data[] = {
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
  };

  const size_t  data_offset = 123;

  memcpy(buf + data_offset, data, sizeof(data));

  const uint8_t reply_address[] = { 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x00 };

  EXPECT_EQ(
      rmap_initialize_header_before(
        &header_offset,
        buf,
        data_offset,
        RMAP_PACKET_TYPE_COMMAND,
        RMAP_COMMAND_CODE_WRITE |
        RMAP_COMMAND_CODE_REPLY |
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
  rmap_set_data_length(header, sizeof(data));

  rmap_calculate_and_set_header_crc(header);

  buf[data_offset + sizeof(data)] =
    rmap_crc_calculate(buf + data_offset, sizeof(data));

  const uint8_t target_address[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };

  memcpy(
      header - sizeof(target_address),
      target_address,
      sizeof(target_address));

  std::vector<uint8_t> packet(
      buf + header_offset - sizeof(target_address),
      buf + data_offset + sizeof(data) + 1);
  EXPECT_EQ(packet, expected_packet);
}

TEST(RmapRecreateHeader, TestPattern2Reply)
{
  uint8_t buf[123];

  std::vector<uint8_t> expected_packet(
      test_pattern2_expected_write_reply_with_spacewire_addresses,
      test_pattern2_expected_write_reply_with_spacewire_addresses +
      sizeof(test_pattern2_expected_write_reply_with_spacewire_addresses));

  memset(buf, 0, sizeof(buf));

  const uint8_t reply_address[] = { 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x00 };

  uint8_t *const header = buf + sizeof(reply_address);

  EXPECT_EQ(
      rmap_initialize_header(
        header,
        sizeof(buf) - sizeof(reply_address),
        RMAP_PACKET_TYPE_REPLY,
        RMAP_COMMAND_CODE_WRITE |
        RMAP_COMMAND_CODE_REPLY |
        RMAP_COMMAND_CODE_INCREMENT,
        sizeof(reply_address)),
      RMAP_OK);

  rmap_set_initiator_logical_address(header, 0x67);
  rmap_set_status(header, RMAP_STATUS_FIELD_CODE_SUCCESS);
  rmap_set_target_logical_address(header, 0xFE);
  rmap_set_transaction_identifier(header, 2);
  rmap_calculate_and_set_header_crc(header);

  memcpy(buf, reply_address, sizeof(reply_address));

  std::vector<uint8_t> packet(
      buf,
      buf + sizeof(reply_address) + rmap_calculate_header_size(header));
  EXPECT_EQ(packet, expected_packet);
}

TEST(RmapRecreateHeader, TestPattern3Command)
{
  uint8_t buf[123];

  std::vector<uint8_t> expected_packet(
      test_pattern3_incrementing_read_with_spacewire_addresses,
      test_pattern3_incrementing_read_with_spacewire_addresses +
      sizeof(test_pattern3_incrementing_read_with_spacewire_addresses));

  memset(buf, 0, sizeof(buf));

  const uint8_t target_address[] = { 0x11, 0x22, 0x33, 0x44 };

  const uint8_t reply_address[] = { 0x99, 0xAA, 0xBB, 0xCC };

  uint8_t *const header = buf + sizeof(target_address);

  EXPECT_EQ(
      rmap_initialize_header(
        header,
        sizeof(buf) - sizeof(target_address),
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

  memcpy(buf, target_address, sizeof(target_address));

  std::vector<uint8_t> packet(
    buf,
    buf + sizeof(target_address) + rmap_calculate_header_size(header));
  EXPECT_EQ(packet, expected_packet);
}

TEST(RmapRecreateHeader, TestPattern3Reply)
{
  size_t header_offset;
  uint8_t buf[1234];

  std::vector<uint8_t> expected_packet(
      test_pattern3_expected_read_reply_with_spacewire_addresses,
      test_pattern3_expected_read_reply_with_spacewire_addresses +
      sizeof(test_pattern3_expected_read_reply_with_spacewire_addresses));

  memset(buf, 0, sizeof(buf));

  const uint8_t reply_address[] = { 0x99, 0xAA, 0xBB, 0xCC };

  const uint8_t data[] = {
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
  };

  const size_t  data_offset = 123;

  memcpy(buf + data_offset, data, sizeof(data));

  EXPECT_EQ(
      rmap_initialize_header_before(
        &header_offset,
        buf,
        data_offset,
        RMAP_PACKET_TYPE_REPLY,
        RMAP_COMMAND_CODE_REPLY | RMAP_COMMAND_CODE_INCREMENT,
        sizeof(reply_address)),
      RMAP_OK);

  uint8_t *const header = buf + header_offset;

  rmap_set_initiator_logical_address(header, 0x67);
  rmap_set_status(header, RMAP_STATUS_FIELD_CODE_SUCCESS);
  rmap_set_target_logical_address(header, 0xFE);
  rmap_set_transaction_identifier(header, 3);
  rmap_set_reserved(header);
  rmap_set_data_length(header, sizeof(data));

  rmap_calculate_and_set_header_crc(header);

  memcpy(
      header - sizeof(reply_address),
      reply_address,
      sizeof(reply_address));

  buf[data_offset + sizeof(data)] =
    rmap_crc_calculate(buf + data_offset, sizeof(data));

  std::vector<uint8_t> packet(
      buf + header_offset - sizeof(reply_address),
      buf + data_offset + sizeof(data) + 1);
  EXPECT_EQ(packet, expected_packet);
}

TEST(RmapCrcCalculate, ZeroesInDataGivesZeroCrc)
{
  unsigned char data[17] = {};

  EXPECT_EQ(rmap_crc_calculate(data, sizeof(data)), 0x00);
}

TEST(RmapCrcCalculate, TestPattern0Command)
{
  const size_t header_length = 16;

  const uint8_t *const pattern =
    test_pattern0_unverified_incrementing_write_with_reply;
  const size_t pattern_length =
    sizeof(test_pattern0_unverified_incrementing_write_with_reply);

  const uint8_t header_received_crc = pattern[header_length - 1];
  const uint8_t header_calculated_excluding_received_crc =
    rmap_crc_calculate(pattern, header_length - 1);
  EXPECT_EQ(header_calculated_excluding_received_crc, header_received_crc);

  const uint8_t header_calculated_including_received_crc =
    rmap_crc_calculate(pattern, header_length);
  EXPECT_EQ(header_calculated_including_received_crc, 0);

  const uint8_t data_received_crc = pattern[pattern_length - 1];
  const uint8_t data_calculated_excluding_received_crc =
    rmap_crc_calculate(
        pattern + header_length,
        pattern_length - header_length - 1);
  EXPECT_EQ(data_calculated_excluding_received_crc, data_received_crc);

  const uint8_t data_calculated_including_received_crc =
    rmap_crc_calculate(pattern + header_length, pattern_length - header_length);
  EXPECT_EQ(data_calculated_including_received_crc, 0);
}

TEST(RmapCrcCalculate, TestPattern0Reply)
{
  const size_t header_length = 8;

  const uint8_t *const pattern =
    test_pattern0_expected_write_reply;

  const uint8_t received_crc = pattern[header_length - 1];
  const uint8_t calculated_excluding_received_crc =
    rmap_crc_calculate(pattern, header_length - 1);
  EXPECT_EQ(calculated_excluding_received_crc, received_crc);
}

TEST(RmapCrcCalculate, TestPattern1Command)
{
  const size_t header_length = 16;

  const uint8_t *const pattern = test_pattern1_incrementing_read;

  const uint8_t received_crc = pattern[header_length - 1];
  const uint8_t calculated_excluding_received_crc =
    rmap_crc_calculate(pattern, header_length - 1);
  EXPECT_EQ(calculated_excluding_received_crc, received_crc);

  const uint8_t calculated_including_received_crc =
    rmap_crc_calculate(pattern, header_length);
  EXPECT_EQ(calculated_including_received_crc, 0);
}

TEST(RmapCrcCalculate, TestPattern1Reply)
{
  const size_t header_length = 12;

  const uint8_t *const pattern = test_pattern1_expected_read_reply;
  const size_t pattern_length = sizeof(test_pattern1_expected_read_reply);

  const uint8_t header_received_crc = pattern[header_length - 1];
  const uint8_t header_calculated_excluding_received_crc =
    rmap_crc_calculate(pattern, header_length - 1);
  EXPECT_EQ(header_calculated_excluding_received_crc, header_received_crc);

  const uint8_t header_calculated_including_received_crc =
    rmap_crc_calculate(pattern, header_length);
  EXPECT_EQ(header_calculated_including_received_crc, 0);

  const uint8_t data_received_crc = pattern[pattern_length - 1];
  const uint8_t data_calculated_excluding_received_crc =
    rmap_crc_calculate(
        pattern + header_length,
        pattern_length - header_length - 1);
  EXPECT_EQ(data_calculated_excluding_received_crc, data_received_crc);

  const uint8_t data_calculated_including_received_crc =
    rmap_crc_calculate(pattern + header_length, pattern_length - header_length);
  EXPECT_EQ(data_calculated_including_received_crc, 0);
}
