#include <gtest/gtest.h>

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

TEST(RmapHeaderDeserialize, Nullptr)
{
  size_t serialized_size;
  rmap_receive_header_t header;

  EXPECT_EQ(
      rmap_header_deserialize(
        NULL,
        &header,
        (unsigned char *)test_pattern1_incrementing_read,
        sizeof(test_pattern1_incrementing_read)),
      RMAP_NULLPTR);

  EXPECT_EQ(
      rmap_header_deserialize(
        &serialized_size,
        NULL,
        (unsigned char *)test_pattern1_incrementing_read,
        sizeof(test_pattern1_incrementing_read)),
      RMAP_NULLPTR);

  EXPECT_EQ(
      rmap_header_deserialize(
        &serialized_size,
        &header,
        NULL,
        sizeof(test_pattern1_incrementing_read)),
      RMAP_NULLPTR);

  EXPECT_EQ(
      rmap_header_deserialize(
        NULL,
        NULL,
        (unsigned char *)test_pattern1_incrementing_read,
        sizeof(test_pattern1_incrementing_read)),
      RMAP_NULLPTR);

  EXPECT_EQ(
      rmap_header_deserialize(
        &serialized_size,
        NULL,
        NULL,
        sizeof(test_pattern1_incrementing_read)),
      RMAP_NULLPTR);

  EXPECT_EQ(
      rmap_header_deserialize(
        NULL,
        NULL,
        NULL,
        sizeof(test_pattern1_incrementing_read)),
      RMAP_NULLPTR);
}

TEST(RmapHeaderDeserialize, TestPattern0Command)
{
  rmap_receive_header_t header;
  size_t serialized_size;

  EXPECT_EQ(
      rmap_header_deserialize(
        &serialized_size,
        &header,
        (unsigned char *)test_pattern0_unverified_incrementing_write_with_reply,
        sizeof(test_pattern0_unverified_incrementing_write_with_reply)),
      RMAP_OK);

  EXPECT_EQ(serialized_size, 16);

  ASSERT_EQ(header.type, RMAP_TYPE_COMMAND);
  EXPECT_EQ(header.t.command.target_logical_address, 0xFE);
  EXPECT_TRUE(header.t.command.command_codes & RMAP_COMMAND_CODE_WRITE);
  EXPECT_FALSE(header.t.command.command_codes & RMAP_COMMAND_CODE_VERIFY);
  EXPECT_TRUE(header.t.command.command_codes & RMAP_COMMAND_CODE_REPLY);
  EXPECT_TRUE(header.t.command.command_codes & RMAP_COMMAND_CODE_INCREMENT);
  EXPECT_EQ(header.t.command.key, 0x00);
  EXPECT_EQ(header.t.command.reply_address.length, 0);
  EXPECT_EQ(header.t.command.initiator_logical_address, 0x67);
  EXPECT_EQ(header.t.command.transaction_identifier, 0x0000);
  EXPECT_EQ(header.t.command.extended_address, 0x00);
  EXPECT_EQ(header.t.command.address, 0xA0000000);
  EXPECT_EQ(header.t.command.data_length, 0x0010);
}

TEST(RmapHeaderDeserialize, TestPattern0Reply)
{
  rmap_receive_header_t header;
  size_t serialized_size;

  EXPECT_EQ(
      rmap_header_deserialize(
        &serialized_size,
        &header,
        (unsigned char *)test_pattern0_expected_write_reply,
        sizeof(test_pattern0_expected_write_reply)),
      RMAP_OK);

  EXPECT_EQ(serialized_size, 8);

  ASSERT_EQ(header.type, RMAP_TYPE_WRITE_REPLY);
  EXPECT_EQ(header.t.write_reply.initiator_logical_address, 0x67);
  EXPECT_TRUE(header.t.write_reply.command_codes & RMAP_COMMAND_CODE_WRITE);
  EXPECT_FALSE(header.t.write_reply.command_codes & RMAP_COMMAND_CODE_VERIFY);
  EXPECT_TRUE(header.t.write_reply.command_codes & RMAP_COMMAND_CODE_REPLY);
  EXPECT_TRUE(header.t.write_reply.command_codes & RMAP_COMMAND_CODE_INCREMENT);
  EXPECT_EQ(header.t.write_reply.status, 0x00);
  EXPECT_EQ(header.t.write_reply.target_logical_address, 0xFE);
  EXPECT_EQ(header.t.write_reply.transaction_identifier, 0x0000);
}
