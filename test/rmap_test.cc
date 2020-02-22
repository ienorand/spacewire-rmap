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

TEST(RmapHeaderDeserialize, TestPattern1Command)
{
  rmap_receive_header_t header;
  size_t serialized_size;

  EXPECT_EQ(
      rmap_header_deserialize(
        &serialized_size,
        &header,
        (unsigned char *)test_pattern1_incrementing_read,
      sizeof(test_pattern1_incrementing_read)),
      RMAP_OK);

  EXPECT_EQ(serialized_size, 16);

  ASSERT_EQ(header.type, RMAP_TYPE_COMMAND);
  EXPECT_EQ(header.t.command.target_logical_address, 0xFE);
  EXPECT_FALSE(header.t.command.command_codes & RMAP_COMMAND_CODE_WRITE);
  EXPECT_FALSE(header.t.command.command_codes & RMAP_COMMAND_CODE_VERIFY);
  EXPECT_TRUE(header.t.command.command_codes & RMAP_COMMAND_CODE_REPLY);
  EXPECT_TRUE(header.t.command.command_codes & RMAP_COMMAND_CODE_INCREMENT);
  EXPECT_EQ(header.t.command.key, 0x00);
  EXPECT_EQ(header.t.command.reply_address.length, 0);
  EXPECT_EQ(header.t.command.initiator_logical_address, 0x67);
  EXPECT_EQ(header.t.command.transaction_identifier, 0x0001);
  EXPECT_EQ(header.t.command.extended_address, 0x00);
  EXPECT_EQ(header.t.command.address, 0xA0000000);
  EXPECT_EQ(header.t.command.data_length, 0x0010);
}

TEST(RmapHeaderDeserialize, TestPattern1Reply)
{
  rmap_receive_header_t header;
  size_t serialized_size;

  EXPECT_EQ(
      rmap_header_deserialize(
        &serialized_size,
        &header,
        (unsigned char *)test_pattern1_expected_read_reply,
        sizeof(test_pattern1_expected_read_reply)),
      RMAP_OK);

  EXPECT_EQ(serialized_size, 12);

  ASSERT_EQ(header.type, RMAP_TYPE_READ_REPLY);
  EXPECT_EQ(header.t.read_reply.initiator_logical_address, 0x67);
  EXPECT_FALSE(header.t.read_reply.command_codes & RMAP_COMMAND_CODE_WRITE);
  EXPECT_FALSE(header.t.read_reply.command_codes & RMAP_COMMAND_CODE_VERIFY);
  EXPECT_TRUE(header.t.read_reply.command_codes & RMAP_COMMAND_CODE_REPLY);
  EXPECT_TRUE(header.t.read_reply.command_codes & RMAP_COMMAND_CODE_INCREMENT);
  EXPECT_EQ(header.t.read_reply.status, 0x00);
  EXPECT_EQ(header.t.read_reply.target_logical_address, 0xFE);
  EXPECT_EQ(header.t.read_reply.transaction_identifier, 0x0001);
}

TEST(RmapHeaderDeserialize, TestPattern2Command)
{
  rmap_receive_header_t header;
  size_t serialized_size;

  const size_t expected_reply_address_padding = 1;
  const unsigned char expected_reply_address[] = {
    0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x00
  };
  ASSERT_EQ(sizeof(expected_reply_address), test_pattern2_reply_address_length);

  EXPECT_EQ(
      rmap_header_deserialize(
        &serialized_size,
        &header,
        (unsigned char *)test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses +
        test_pattern2_target_address_length,
        sizeof(test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses) -
        test_pattern2_target_address_length),
      RMAP_OK);

  EXPECT_EQ(
      serialized_size,
      16 + expected_reply_address_padding + sizeof(expected_reply_address));

  ASSERT_EQ(header.type, RMAP_TYPE_COMMAND);
  EXPECT_EQ(header.t.command.target_logical_address, 0xFE);
  EXPECT_TRUE(header.t.command.command_codes & RMAP_COMMAND_CODE_WRITE);
  EXPECT_FALSE(header.t.command.command_codes & RMAP_COMMAND_CODE_VERIFY);
  EXPECT_TRUE(header.t.command.command_codes & RMAP_COMMAND_CODE_REPLY);
  EXPECT_TRUE(header.t.command.command_codes & RMAP_COMMAND_CODE_INCREMENT);
  EXPECT_EQ(header.t.command.key, 0x00);
  EXPECT_EQ(
      header.t.command.reply_address.length,
      sizeof(expected_reply_address));
  EXPECT_EQ(
      std::vector<unsigned char>(
        header.t.command.reply_address.data,
        header.t.command.reply_address.data +
        header.t.command.reply_address.length),
      std::vector<unsigned char>(
        std::begin(expected_reply_address),
        std::end(expected_reply_address)));
  EXPECT_EQ(header.t.command.initiator_logical_address, 0x67);
  EXPECT_EQ(header.t.command.transaction_identifier, 0x0002);
  EXPECT_EQ(header.t.command.extended_address, 0x00);
  EXPECT_EQ(header.t.command.address, 0xA0000010);
  EXPECT_EQ(header.t.command.data_length, 0x0010);
}

TEST(RmapHeaderDeserialize, TestPattern2Reply)
{
  rmap_receive_header_t header;
  size_t serialized_size;

  EXPECT_EQ(
      rmap_header_deserialize(
        &serialized_size,
        &header,
        (unsigned char *)test_pattern2_expected_write_reply_with_spacewire_addresses +
        test_pattern2_reply_address_length,
        sizeof(test_pattern2_expected_write_reply_with_spacewire_addresses) -
        test_pattern2_reply_address_length),
      RMAP_OK);

  EXPECT_EQ(serialized_size, 8);

  ASSERT_EQ(header.type, RMAP_TYPE_WRITE_REPLY);
  EXPECT_EQ(header.t.read_reply.initiator_logical_address, 0x67);
  EXPECT_TRUE(header.t.read_reply.command_codes & RMAP_COMMAND_CODE_WRITE);
  EXPECT_FALSE(header.t.read_reply.command_codes & RMAP_COMMAND_CODE_VERIFY);
  EXPECT_TRUE(header.t.read_reply.command_codes & RMAP_COMMAND_CODE_REPLY);
  EXPECT_TRUE(header.t.read_reply.command_codes & RMAP_COMMAND_CODE_INCREMENT);
  EXPECT_EQ(header.t.read_reply.status, 0x00);
  EXPECT_EQ(header.t.read_reply.target_logical_address, 0xFE);
  EXPECT_EQ(header.t.read_reply.transaction_identifier, 0x0002);
}

TEST(RmapHeaderSerialize, Nullptr)
{
  size_t serialized_size;
  rmap_send_header_t header_tmp;
  unsigned char data[64];

  const uint8_t target_address[] = { 0x1 };
  const uint8_t reply_address[] = { 0x2 };

  header_tmp.type = RMAP_TYPE_COMMAND;
  header_tmp.t.command.target_address.length = sizeof(target_address);
  header_tmp.t.command.target_address.data = target_address;
  header_tmp.t.command.target_logical_address = 0xFE;
  header_tmp.t.command.command_codes =
    RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY;
  header_tmp.t.command.key = 0x00;
  header_tmp.t.command.reply_address.length = sizeof(reply_address);
  memcpy(
      header_tmp.t.command.reply_address.data,
      reply_address,
      sizeof(reply_address));
  header_tmp.t.command.initiator_logical_address = 0x67;
  header_tmp.t.command.transaction_identifier = 0x0000;
  header_tmp.t.command.extended_address = 0x00;
  header_tmp.t.command.address = 0xA0000000;
  header_tmp.t.command.data_length = 0x10;

  const rmap_send_header_t valid_header = header_tmp;

  header_tmp.t.command.target_address.data = NULL;
  const rmap_send_header_t invalid_header_null_target_address = header_tmp;

  header_tmp.t.command.target_address.data = NULL;
  const rmap_send_header_t invalid_header_null_addresses = header_tmp;

  EXPECT_EQ(
      rmap_header_serialize(NULL, data, sizeof(data), &valid_header),
      RMAP_NULLPTR);
  EXPECT_EQ(
      rmap_header_serialize(
        &serialized_size,
        NULL,
        sizeof(data),
        &valid_header),
      RMAP_NULLPTR);
  EXPECT_EQ(
      rmap_header_serialize(
        &serialized_size,
        data,
        sizeof(data),
        &invalid_header_null_target_address),
      RMAP_NULLPTR);
  EXPECT_EQ(
      rmap_header_serialize(
        &serialized_size,
        data,
        sizeof(data),
        &invalid_header_null_addresses),
      RMAP_NULLPTR);
  EXPECT_EQ(
      rmap_header_serialize(NULL, NULL, sizeof(data), NULL),
      RMAP_NULLPTR);
}

TEST(RmapHeaderSerialize, InvalidPacketType)
{
  size_t serialized_size;
  rmap_send_header_t header;
  unsigned char data[64];

  const uint8_t target_address[] = { 0x1 };
  const uint8_t reply_address[] = { 0x2 };

  /* Valid write command. */
  header.type = RMAP_TYPE_COMMAND;
  header.t.command.target_address.length = sizeof(target_address);
  header.t.command.target_address.data = target_address;
  header.t.command.target_logical_address = 0xFE;
  header.t.command.command_codes =
    RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY;
  header.t.command.key = 0x00;
  header.t.command.reply_address.length = sizeof(reply_address);
  memcpy(
      header.t.command.reply_address.data,
      reply_address,
      sizeof(reply_address));
  header.t.command.initiator_logical_address = 0x67;
  header.t.command.transaction_identifier = 0x0000;
  header.t.command.extended_address = 0x00;
  header.t.command.address = 0xA0000000;
  header.t.command.data_length = 0x10;

  header.type = (rmap_type_t)-1;
  EXPECT_EQ(
      rmap_header_serialize(
        &serialized_size,
        data,
        sizeof(data),
        &header),
      RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE);

  header.type = (rmap_type_t)(RMAP_TYPE_READ_REPLY + 1);
  EXPECT_EQ(
      rmap_header_serialize(
        &serialized_size,
        data,
        sizeof(data),
        &header),
      RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE);
}

typedef std::tuple<unsigned char, rmap_status_t> CommandCodesStatusParameters;
typedef std::tuple<rmap_type_t, CommandCodesStatusParameters> CommandCodesParameters;
class CommandCodesParameterized :
  public testing::TestWithParam<CommandCodesParameters>
{
};

TEST_P(CommandCodesParameterized, RmapHeaderSerialize)
{
  size_t serialized_size;
  rmap_send_header_t header;
  unsigned char data[64];
  unsigned char expected_result;

  const uint8_t target_address[] = { 0x1 };
  const uint8_t reply_address[] = { 0x2 };

  header.type = std::get<0>(GetParam());
  switch(header.type) {
    case RMAP_TYPE_COMMAND:
      header.t.command.target_address.length = sizeof(target_address);
      header.t.command.target_address.data = target_address;
      header.t.command.target_logical_address = 0xFE;
      header.t.command.key = 0x00;
      header.t.command.reply_address.length = sizeof(reply_address);
      memcpy(
          header.t.command.reply_address.data,
          reply_address,
          sizeof(reply_address));
      header.t.command.initiator_logical_address = 0x67;
      header.t.command.transaction_identifier = 0x0000;
      header.t.command.extended_address = 0x00;
      header.t.command.address = 0xA0000000;
      header.t.command.data_length = 0x10;

      header.t.command.command_codes = std::get<0>(std::get<1>(GetParam()));
      expected_result = std::get<1>(std::get<1>(GetParam()));
      break;

    case RMAP_TYPE_WRITE_REPLY:
      header.t.write_reply.reply_address.length = sizeof(reply_address);
      memcpy(
          header.t.write_reply.reply_address.data,
          reply_address,
          sizeof(reply_address));
      header.t.write_reply.initiator_logical_address = 0xFE;
      header.t.write_reply.status = 0x00;
      header.t.write_reply.target_logical_address = 0x67;
      header.t.write_reply.transaction_identifier = 0x0000;

      header.t.write_reply.command_codes = std::get<0>(std::get<1>(GetParam()));
      expected_result = std::get<1>(std::get<1>(GetParam()));
      break;

    case RMAP_TYPE_READ_REPLY:
      header.t.read_reply.reply_address.length = sizeof(reply_address);
      memcpy(
          header.t.read_reply.reply_address.data,
          reply_address,
          sizeof(reply_address));
      header.t.read_reply.initiator_logical_address = 0xFE;
      header.t.read_reply.status = 0x00;
      header.t.read_reply.target_logical_address = 0x67;
      header.t.read_reply.transaction_identifier = 0x0000;
      header.t.read_reply.data_length = 0x10;

      header.t.read_reply.command_codes = std::get<0>(std::get<1>(GetParam()));
      expected_result = std::get<1>(std::get<1>(GetParam()));
      break;

    default:
      assert(false);
      break;
  }

  EXPECT_EQ(
      rmap_header_serialize(
        &serialized_size,
        data,
        sizeof(data),
        &header),
      expected_result);
}

INSTANTIATE_TEST_CASE_P(
    Command,
    CommandCodesParameterized,
    testing::Combine(
      testing::Values(RMAP_TYPE_COMMAND),
      testing::Values(
        std::make_tuple(
          0x00,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE),
        std::make_tuple(
          RMAP_COMMAND_CODE_INCREMENT,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE),
        std::make_tuple(
          RMAP_COMMAND_CODE_REPLY,
          RMAP_OK),
        std::make_tuple(
          RMAP_COMMAND_CODE_REPLY | RMAP_COMMAND_CODE_INCREMENT,
          RMAP_OK),
        std::make_tuple(
          RMAP_COMMAND_CODE_VERIFY,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE),
        std::make_tuple(
          RMAP_COMMAND_CODE_VERIFY | RMAP_COMMAND_CODE_INCREMENT,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE),
        std::make_tuple(
          RMAP_COMMAND_CODE_VERIFY | RMAP_COMMAND_CODE_REPLY,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE),
        std::make_tuple(
          RMAP_COMMAND_CODE_VERIFY |
            RMAP_COMMAND_CODE_REPLY |
            RMAP_COMMAND_CODE_INCREMENT,
          RMAP_OK),
        std::make_tuple(
          RMAP_COMMAND_CODE_WRITE,
          RMAP_OK),
        std::make_tuple(
          RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_INCREMENT,
          RMAP_OK),
        std::make_tuple(
          RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
          RMAP_OK),
        std::make_tuple(
          RMAP_COMMAND_CODE_WRITE |
            RMAP_COMMAND_CODE_REPLY |
            RMAP_COMMAND_CODE_INCREMENT,
          RMAP_OK),
        std::make_tuple(
          RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_VERIFY,
          RMAP_OK),
        std::make_tuple(
          RMAP_COMMAND_CODE_WRITE |
            RMAP_COMMAND_CODE_VERIFY |
            RMAP_COMMAND_CODE_INCREMENT,
          RMAP_OK),
        std::make_tuple(
          RMAP_COMMAND_CODE_WRITE |
            RMAP_COMMAND_CODE_VERIFY |
            RMAP_COMMAND_CODE_REPLY,
          RMAP_OK),
        std::make_tuple(
          RMAP_COMMAND_CODE_WRITE |
            RMAP_COMMAND_CODE_VERIFY |
            RMAP_COMMAND_CODE_REPLY |
            RMAP_COMMAND_CODE_INCREMENT,
          RMAP_OK),
        std::make_tuple(
          0xFF,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE),
        std::make_tuple(
          (RMAP_COMMAND_CODE_WRITE |
           RMAP_COMMAND_CODE_VERIFY |
           RMAP_COMMAND_CODE_REPLY |
           RMAP_COMMAND_CODE_INCREMENT) + 1,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE))));

INSTANTIATE_TEST_CASE_P(
    WriteReply,
    CommandCodesParameterized,
    testing::Combine(
      testing::Values(RMAP_TYPE_WRITE_REPLY),
      testing::Values(
        std::make_tuple(
          0x00,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE),
        std::make_tuple(
          RMAP_COMMAND_CODE_INCREMENT,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE),
        std::make_tuple(
          RMAP_COMMAND_CODE_REPLY,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE),
        std::make_tuple(
          RMAP_COMMAND_CODE_REPLY | RMAP_COMMAND_CODE_INCREMENT,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE),
        std::make_tuple(
          RMAP_COMMAND_CODE_VERIFY,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE),
        std::make_tuple(
          RMAP_COMMAND_CODE_VERIFY | RMAP_COMMAND_CODE_INCREMENT,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE),
        std::make_tuple(
          RMAP_COMMAND_CODE_VERIFY | RMAP_COMMAND_CODE_REPLY,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE),
        std::make_tuple(
          RMAP_COMMAND_CODE_VERIFY |
            RMAP_COMMAND_CODE_REPLY |
            RMAP_COMMAND_CODE_INCREMENT,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE),
        std::make_tuple(
          RMAP_COMMAND_CODE_WRITE,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE),
        std::make_tuple(
          RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_INCREMENT,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE),
        std::make_tuple(
          RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
          RMAP_OK),
        std::make_tuple(
          RMAP_COMMAND_CODE_WRITE |
            RMAP_COMMAND_CODE_REPLY |
            RMAP_COMMAND_CODE_INCREMENT,
          RMAP_OK),
        std::make_tuple(
          RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_VERIFY,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE),
        std::make_tuple(
          RMAP_COMMAND_CODE_WRITE |
            RMAP_COMMAND_CODE_VERIFY |
            RMAP_COMMAND_CODE_INCREMENT,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE),
        std::make_tuple(
          RMAP_COMMAND_CODE_WRITE |
            RMAP_COMMAND_CODE_VERIFY |
            RMAP_COMMAND_CODE_REPLY,
          RMAP_OK),
        std::make_tuple(
          RMAP_COMMAND_CODE_WRITE |
            RMAP_COMMAND_CODE_VERIFY |
            RMAP_COMMAND_CODE_REPLY |
            RMAP_COMMAND_CODE_INCREMENT,
          RMAP_OK),
        std::make_tuple(
          0xFF,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE),
        std::make_tuple(
          (RMAP_COMMAND_CODE_WRITE |
           RMAP_COMMAND_CODE_VERIFY |
           RMAP_COMMAND_CODE_REPLY |
           RMAP_COMMAND_CODE_INCREMENT) + 1,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE))));

INSTANTIATE_TEST_CASE_P(
    ReadReply,
    CommandCodesParameterized,
    testing::Combine(
      testing::Values(RMAP_TYPE_READ_REPLY),
      testing::Values(
        std::make_tuple(
          0x00,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE),
        std::make_tuple(
          RMAP_COMMAND_CODE_INCREMENT,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE),
        std::make_tuple(
          RMAP_COMMAND_CODE_REPLY,
          RMAP_OK),
        std::make_tuple(
          RMAP_COMMAND_CODE_REPLY | RMAP_COMMAND_CODE_INCREMENT,
          RMAP_OK),
        std::make_tuple(
          RMAP_COMMAND_CODE_VERIFY,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE),
        std::make_tuple(
          RMAP_COMMAND_CODE_VERIFY | RMAP_COMMAND_CODE_INCREMENT,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE),
        std::make_tuple(
          RMAP_COMMAND_CODE_VERIFY | RMAP_COMMAND_CODE_REPLY,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE),
        std::make_tuple(
          RMAP_COMMAND_CODE_VERIFY |
            RMAP_COMMAND_CODE_REPLY |
            RMAP_COMMAND_CODE_INCREMENT,
          RMAP_OK),
        std::make_tuple(
          RMAP_COMMAND_CODE_WRITE,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE),
        std::make_tuple(
          RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_INCREMENT,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE),
        std::make_tuple(
          RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE),
        std::make_tuple(
          RMAP_COMMAND_CODE_WRITE |
            RMAP_COMMAND_CODE_REPLY |
            RMAP_COMMAND_CODE_INCREMENT,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE),
        std::make_tuple(
          RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_VERIFY,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE),
        std::make_tuple(
          RMAP_COMMAND_CODE_WRITE |
            RMAP_COMMAND_CODE_VERIFY |
            RMAP_COMMAND_CODE_INCREMENT,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE),
        std::make_tuple(
          RMAP_COMMAND_CODE_WRITE |
            RMAP_COMMAND_CODE_VERIFY |
            RMAP_COMMAND_CODE_REPLY,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE),
        std::make_tuple(
          RMAP_COMMAND_CODE_WRITE |
            RMAP_COMMAND_CODE_VERIFY |
            RMAP_COMMAND_CODE_REPLY |
            RMAP_COMMAND_CODE_INCREMENT,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE),
        std::make_tuple(
          0xFF,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE),
        std::make_tuple(
          (RMAP_COMMAND_CODE_WRITE |
           RMAP_COMMAND_CODE_VERIFY |
           RMAP_COMMAND_CODE_REPLY |
           RMAP_COMMAND_CODE_INCREMENT) + 1,
          RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE))));

TEST(RmapHeaderSerialize, WriteCommandNotEnoughSpace)
{
  size_t serialized_size;
  rmap_send_header_t header;
  unsigned char data[64];

  const uint8_t target_address[] = { 0x1 };
  const uint8_t reply_address[] = { 0x2 };

  header.type = RMAP_TYPE_COMMAND;
  header.t.command.target_address.length = sizeof(target_address);
  header.t.command.target_address.data = target_address;
  header.t.command.target_logical_address = 0xFE;
  header.t.command.command_codes =
    RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY;
  header.t.command.key = 0x00;
  header.t.command.reply_address.length = sizeof(reply_address);
  memcpy(
    header.t.command.reply_address.data,
    reply_address,
    sizeof(reply_address));
  header.t.command.initiator_logical_address = 0x67;
  header.t.command.transaction_identifier = 0x0000;
  header.t.command.extended_address = 0x00;
  header.t.command.address = 0xA0000000;
  header.t.command.data_length = 0x10;

  /* Write command header is target address plus 16 bytes fixed header plus 4
   * bytes reply address (padded from 1 to a multiple of 4 bytes).
   */
  const size_t one_less_than_needed_size = sizeof(target_address) + 16 + 4 - 1;
  EXPECT_EQ(
      rmap_header_serialize(
        &serialized_size,
        data,
        one_less_than_needed_size,
        &header),
      RMAP_NOT_ENOUGH_SPACE);
}

TEST(RmapHeaderSerialize, WriteCommandExactlyEnoughSpace)
{
  size_t serialized_size;
  rmap_send_header_t header;
  unsigned char data[64];

  const uint8_t target_address[] = { 0x1 };
  const uint8_t reply_address[] = { 0x2 };

  header.type = RMAP_TYPE_COMMAND;
  header.t.command.target_address.length = sizeof(target_address);
  header.t.command.target_address.data = target_address;
  header.t.command.target_logical_address = 0xFE;
  header.t.command.command_codes =
    RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY;
  header.t.command.key = 0x00;
  header.t.command.reply_address.length = sizeof(reply_address);
  memcpy(
    header.t.command.reply_address.data,
    reply_address,
    sizeof(reply_address));
  header.t.command.initiator_logical_address = 0x67;
  header.t.command.transaction_identifier = 0x0000;
  header.t.command.extended_address = 0x00;
  header.t.command.address = 0xA0000000;
  header.t.command.data_length = 0x10;

  /* Write command header is target address plus 16 bytes fixed header plus 4
   * bytes reply address (padded from 1 to a multiple of 4 bytes).
   */
  const size_t exactly_needed_size = sizeof(target_address) + 16 + 4;
  EXPECT_EQ(
      rmap_header_serialize(
        &serialized_size,
        data,
        exactly_needed_size,
        &header),
      RMAP_OK);
}

TEST(RmapHeaderSerialize, WriteCommandReplyAddressTooLong)
{
  size_t serialized_size;
  rmap_send_header_t header;
  unsigned char data[64];

  const uint8_t target_address[] = { 0x1 };
  const uint8_t maximum_reply_address[] = {
    0x2, 0x3, 0x4, 0x5,
    0x6, 0x7, 0x8, 0x9,
    0xA, 0xB, 0xC, 0xD
  };

  header.type = RMAP_TYPE_COMMAND;
  header.t.command.target_address.length = sizeof(target_address);
  header.t.command.target_address.data = target_address;
  header.t.command.target_logical_address = 0xFE;
  header.t.command.command_codes =
    RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY;
  header.t.command.key = 0x00;
  header.t.command.reply_address.length = sizeof(maximum_reply_address) + 1;
  memcpy(
    header.t.command.reply_address.data,
    maximum_reply_address,
    sizeof(maximum_reply_address));
  header.t.command.initiator_logical_address = 0x67;
  header.t.command.transaction_identifier = 0x0000;
  header.t.command.extended_address = 0x00;
  header.t.command.address = 0xA0000000;
  header.t.command.data_length = 0x10;

  EXPECT_EQ(
      rmap_header_serialize(
        &serialized_size,
        data,
        sizeof(data),
        &header),
      RMAP_REPLY_ADDRESS_TOO_LONG);
}

TEST(RmapHeaderSerialize, WriteCommandDataLengthTooBig)
{
  size_t serialized_size;
  rmap_send_header_t header;
  unsigned char data[64];

  const uint8_t target_address[] = { 0x1 };
  const uint8_t reply_address[] = { 0x2 };

  header.type = RMAP_TYPE_COMMAND;
  header.t.command.target_address.length = sizeof(target_address);
  header.t.command.target_address.data = target_address;
  header.t.command.target_logical_address = 0xFE;
  header.t.command.command_codes =
    RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY;
  header.t.command.key = 0x00;
  header.t.command.reply_address.length = sizeof(reply_address);
  memcpy(
    header.t.command.reply_address.data,
    reply_address,
    sizeof(reply_address));
  header.t.command.initiator_logical_address = 0x67;
  header.t.command.transaction_identifier = 0x0000;
  header.t.command.extended_address = 0x00;
  header.t.command.address = 0xA0000000;
  header.t.command.data_length = 1 << 24;

  EXPECT_EQ(
      rmap_header_serialize(
        &serialized_size,
        data,
        sizeof(data),
        &header),
      RMAP_DATA_LENGTH_TOO_BIG);
}

TEST(RmapHeaderSerialize, WriteCommandMaximumDataLength)
{
  size_t serialized_size;
  rmap_send_header_t header;
  unsigned char data[64];

  const uint8_t target_address[] = { 0x1 };
  const uint8_t reply_address[] = { 0x2 };

  header.type = RMAP_TYPE_COMMAND;
  header.t.command.target_address.length = sizeof(target_address);
  header.t.command.target_address.data = target_address;
  header.t.command.target_logical_address = 0xFE;
  header.t.command.command_codes =
    RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY;
  header.t.command.key = 0x00;
  header.t.command.reply_address.length = sizeof(reply_address);
  memcpy(
    header.t.command.reply_address.data,
    reply_address,
    sizeof(reply_address));
  header.t.command.initiator_logical_address = 0x67;
  header.t.command.transaction_identifier = 0x0000;
  header.t.command.extended_address = 0x00;
  header.t.command.address = 0xA0000000;
  header.t.command.data_length = (1 << 24) - 1;

  EXPECT_EQ(
      rmap_header_serialize(
        &serialized_size,
        data,
        sizeof(data),
        &header),
      RMAP_OK);
}

TEST(RmapHeaderSerialize, WriteCommandMaximumReplyAddressLength)
{
  size_t serialized_size;
  rmap_send_header_t header;
  unsigned char data[64];

  const uint8_t target_address[] = { 0x1 };
  const uint8_t maximum_reply_address[] = {
    0x2, 0x3, 0x4, 0x5,
    0x6, 0x7, 0x8, 0x9,
    0xA, 0xB, 0xC, 0xD
  };

  header.type = RMAP_TYPE_COMMAND;
  header.t.command.target_address.length = sizeof(target_address);
  header.t.command.target_address.data = target_address;
  header.t.command.target_logical_address = 0xFE;
  header.t.command.command_codes =
    RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY;
  header.t.command.key = 0x00;
  header.t.command.reply_address.length = sizeof(maximum_reply_address);
  memcpy(
    header.t.command.reply_address.data,
    maximum_reply_address,
    sizeof(maximum_reply_address));
  header.t.command.initiator_logical_address = 0x67;
  header.t.command.transaction_identifier = 0x0000;
  header.t.command.extended_address = 0x00;
  header.t.command.address = 0xA0000000;
  header.t.command.data_length = 0x10;

  EXPECT_EQ(
      rmap_header_serialize(
        &serialized_size,
        data,
        sizeof(data),
        &header),
      RMAP_OK);
}

TEST(RmapHeaderSerialize, ReadCommandNotEnoughSpace)
{
  size_t serialized_size;
  rmap_send_header_t header;
  unsigned char data[64];

  const uint8_t target_address[] = { 0x1 };
  const uint8_t reply_address[] = { 0x2 };

  header.type = RMAP_TYPE_COMMAND;
  header.t.command.target_address.length = sizeof(target_address);
  header.t.command.target_address.data = target_address;
  header.t.command.target_logical_address = 0xFE;
  header.t.command.command_codes = RMAP_COMMAND_CODE_REPLY;
  header.t.command.key = 0x00;
  header.t.command.reply_address.length = sizeof(reply_address);
  memcpy(
    header.t.command.reply_address.data,
    reply_address,
    sizeof(reply_address));
  header.t.command.initiator_logical_address = 0x67;
  header.t.command.transaction_identifier = 0x0000;
  header.t.command.extended_address = 0x00;
  header.t.command.address = 0xA0000000;
  header.t.command.data_length = 0x10;

  /* Read command header is target address plus 16 bytes fixed header plus 4
   * bytes reply address (padded from 1 to a multiple of 4 bytes).
   */
  const size_t one_less_than_needed_size = sizeof(target_address) + 16 + 4 - 1;
  EXPECT_EQ(
      rmap_header_serialize(
        &serialized_size,
        data,
        one_less_than_needed_size,
        &header),
      RMAP_NOT_ENOUGH_SPACE);
}

TEST(RmapHeaderSerialize, ReadCommandExactlyEnoughSpace)
{
  size_t serialized_size;
  rmap_send_header_t header;
  unsigned char data[64];

  const uint8_t target_address[] = { 0x1 };
  const uint8_t reply_address[] = { 0x2 };

  header.type = RMAP_TYPE_COMMAND;
  header.t.command.target_address.length = sizeof(target_address);
  header.t.command.target_address.data = target_address;
  header.t.command.target_logical_address = 0xFE;
  header.t.command.command_codes = RMAP_COMMAND_CODE_REPLY;
  header.t.command.key = 0x00;
  header.t.command.reply_address.length = sizeof(reply_address);
  memcpy(
    header.t.command.reply_address.data,
    reply_address,
    sizeof(reply_address));
  header.t.command.initiator_logical_address = 0x67;
  header.t.command.transaction_identifier = 0x0000;
  header.t.command.extended_address = 0x00;
  header.t.command.address = 0xA0000000;
  header.t.command.data_length = 0x10;

  /* Read command header is target address plus 16 bytes fixed header plus 4
   * bytes reply address (padded from 1 to a multiple of 4 bytes).
   */
  const size_t exactly_needed_size = sizeof(target_address) + 16 + 4;
  EXPECT_EQ(
      rmap_header_serialize(
        &serialized_size,
        data,
        exactly_needed_size,
        &header),
      RMAP_OK);
}

TEST(RmapHeaderSerialize, ReadCommandReplyAddressTooLong)
{
  size_t serialized_size;
  rmap_send_header_t header;
  unsigned char data[64];

  const uint8_t target_address[] = { 0x1 };
  const uint8_t maximum_reply_address[] = {
    0x2, 0x3, 0x4, 0x5,
    0x6, 0x7, 0x8, 0x9,
    0xA, 0xB, 0xC, 0xD
  };

  header.type = RMAP_TYPE_COMMAND;
  header.t.command.target_address.length = sizeof(target_address);
  header.t.command.target_address.data = target_address;
  header.t.command.target_logical_address = 0xFE;
  header.t.command.command_codes = RMAP_COMMAND_CODE_REPLY;
  header.t.command.key = 0x00;
  header.t.command.reply_address.length = sizeof(maximum_reply_address) + 1;
  memcpy(
    header.t.command.reply_address.data,
    maximum_reply_address,
    sizeof(maximum_reply_address));
  header.t.command.initiator_logical_address = 0x67;
  header.t.command.transaction_identifier = 0x0000;
  header.t.command.extended_address = 0x00;
  header.t.command.address = 0xA0000000;
  header.t.command.data_length = 0x10;

  EXPECT_EQ(
      rmap_header_serialize(
        &serialized_size,
        data,
        sizeof(data),
        &header),
      RMAP_REPLY_ADDRESS_TOO_LONG);
}

TEST(RmapHeaderSerialize, ReadCommandMaximumReplyAddressLength)
{
  size_t serialized_size;
  rmap_send_header_t header;
  unsigned char data[64];

  const uint8_t target_address[] = { 0x1 };
  const uint8_t maximum_reply_address[] = {
    0x2, 0x3, 0x4, 0x5,
    0x6, 0x7, 0x8, 0x9,
    0xA, 0xB, 0xC, 0xD
  };

  header.type = RMAP_TYPE_COMMAND;
  header.t.command.target_address.length = sizeof(target_address);
  header.t.command.target_address.data = target_address;
  header.t.command.target_logical_address = 0xFE;
  header.t.command.command_codes = RMAP_COMMAND_CODE_REPLY;
  header.t.command.key = 0x00;
  header.t.command.reply_address.length = sizeof(maximum_reply_address);
  memcpy(
    header.t.command.reply_address.data,
    maximum_reply_address,
    sizeof(maximum_reply_address));
  header.t.command.initiator_logical_address = 0x67;
  header.t.command.transaction_identifier = 0x0000;
  header.t.command.extended_address = 0x00;
  header.t.command.address = 0xA0000000;
  header.t.command.data_length = 0x10;

  EXPECT_EQ(
      rmap_header_serialize(
        &serialized_size,
        data,
        sizeof(data),
        &header),
      RMAP_OK);
}

TEST(RmapHeaderSerialize, ReadCommandDataLengthTooBig)
{
  size_t serialized_size;
  rmap_send_header_t header;
  unsigned char data[64];

  const uint8_t target_address[] = { 0x1 };
  const uint8_t reply_address[] = { 0x2 };

  header.type = RMAP_TYPE_COMMAND;
  header.t.command.target_address.length = sizeof(target_address);
  header.t.command.target_address.data = target_address;
  header.t.command.target_logical_address = 0xFE;
  header.t.command.command_codes = RMAP_COMMAND_CODE_REPLY;
  header.t.command.key = 0x00;
  header.t.command.reply_address.length = sizeof(reply_address);
  memcpy(
    header.t.command.reply_address.data,
    reply_address,
    sizeof(reply_address));
  header.t.command.initiator_logical_address = 0x67;
  header.t.command.transaction_identifier = 0x0000;
  header.t.command.extended_address = 0x00;
  header.t.command.address = 0xA0000000;
  header.t.command.data_length = 1 << 24;

  EXPECT_EQ(
      rmap_header_serialize(
        &serialized_size,
        data,
        sizeof(data),
        &header),
      RMAP_DATA_LENGTH_TOO_BIG);
}

TEST(RmapHeaderSerialize, ReadCommandMaximumDataLength)
{
  size_t serialized_size;
  rmap_send_header_t header;
  unsigned char data[64];

  const uint8_t target_address[] = { 0x1 };
  const uint8_t reply_address[] = { 0x2 };

  header.type = RMAP_TYPE_COMMAND;
  header.t.command.target_address.length = sizeof(target_address);
  header.t.command.target_address.data = target_address;
  header.t.command.target_logical_address = 0xFE;
  header.t.command.command_codes = RMAP_COMMAND_CODE_REPLY;
  header.t.command.key = 0x00;
  header.t.command.reply_address.length = sizeof(reply_address);
  memcpy(
    header.t.command.reply_address.data,
    reply_address,
    sizeof(reply_address));
  header.t.command.initiator_logical_address = 0x67;
  header.t.command.transaction_identifier = 0x0000;
  header.t.command.extended_address = 0x00;
  header.t.command.address = 0xA0000000;
  header.t.command.data_length = (1 << 24) - 1;

  EXPECT_EQ(
      rmap_header_serialize(
        &serialized_size,
        data,
        sizeof(data),
        &header),
      RMAP_OK);
}

TEST(RmapHeaderSerialize, SendWriteReplyNotEnoughSpace)
{
  size_t serialized_size;
  rmap_send_header_t header;
  unsigned char data[64];

  const uint8_t reply_address[] = { 0x1 };

  header.type = RMAP_TYPE_WRITE_REPLY;
  header.t.write_reply.reply_address.length = sizeof(reply_address);
  memcpy(
    header.t.write_reply.reply_address.data,
    reply_address,
    sizeof(reply_address));
  header.t.write_reply.initiator_logical_address = 0xFE;
  header.t.write_reply.command_codes =
    RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY;
  header.t.write_reply.status = 0x00;
  header.t.write_reply.target_logical_address = 0x67;
  header.t.write_reply.transaction_identifier = 0x0000;

  /* Write reply header is reply address plus 8 bytes fixed header. */
  const size_t one_less_than_needed_size = sizeof(reply_address) + 8 - 1;
  EXPECT_EQ(
      rmap_header_serialize(
        &serialized_size,
        data,
        one_less_than_needed_size,
        &header),
      RMAP_NOT_ENOUGH_SPACE);
}

TEST(RmapHeaderSerialize, SendWriteReplyExactlyEnoughSpace)
{
  size_t serialized_size;
  rmap_send_header_t header;
  unsigned char data[64];

  const uint8_t reply_address[] = { 0x1 };

  header.type = RMAP_TYPE_WRITE_REPLY;
  header.t.write_reply.reply_address.length = sizeof(reply_address);
  memcpy(
    header.t.write_reply.reply_address.data,
    reply_address,
    sizeof(reply_address));
  header.t.write_reply.initiator_logical_address = 0xFE;
  header.t.write_reply.command_codes =
    RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY;
  header.t.write_reply.status = 0x00;
  header.t.write_reply.target_logical_address = 0x67;
  header.t.write_reply.transaction_identifier = 0x0000;

  /* Write reply header is reply address plus 8 bytes fixed header. */
  const size_t exactly_needed_size = sizeof(reply_address) + 8;
  EXPECT_EQ(
      rmap_header_serialize(
        &serialized_size,
        data,
        exactly_needed_size,
        &header),
      RMAP_OK);
}

TEST(RmapHeaderSerialize, SendWriteReplyReplyAddressTooLong)
{
  size_t serialized_size;
  rmap_send_header_t header;
  unsigned char data[64];

  const uint8_t maximum_reply_address[] = {
    0x1, 0x2, 0x3, 0x4,
    0x5, 0x6, 0x7, 0x8,
    0x9, 0xA, 0xB, 0xC
  };

  header.type = RMAP_TYPE_WRITE_REPLY;
  header.t.write_reply.reply_address.length = sizeof(maximum_reply_address) + 1;
  memcpy(
    header.t.write_reply.reply_address.data,
    maximum_reply_address,
    sizeof(maximum_reply_address));
  header.t.write_reply.initiator_logical_address = 0xFE;
  header.t.write_reply.command_codes =
    RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY;
  header.t.write_reply.status = 0x00;
  header.t.write_reply.target_logical_address = 0x67;
  header.t.write_reply.transaction_identifier = 0x0000;

  EXPECT_EQ(
      rmap_header_serialize(&serialized_size, data, sizeof(data), &header),
      RMAP_REPLY_ADDRESS_TOO_LONG);
}

TEST(RmapHeaderSerialize, SendWriteReplyMaximumReplyAddressLength)
{
  size_t serialized_size;
  rmap_send_header_t header;
  unsigned char data[64];

  const uint8_t maximum_reply_address[] = {
    0x1, 0x2, 0x3, 0x4,
    0x5, 0x6, 0x7, 0x8,
    0x9, 0xA, 0xB, 0xC
  };

  header.type = RMAP_TYPE_WRITE_REPLY;
  header.t.write_reply.reply_address.length = sizeof(maximum_reply_address);
  memcpy(
    header.t.write_reply.reply_address.data,
    maximum_reply_address,
    sizeof(maximum_reply_address));
  header.t.write_reply.initiator_logical_address = 0xFE;
  header.t.write_reply.command_codes =
    RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY;
  header.t.write_reply.status = 0x00;
  header.t.write_reply.target_logical_address = 0x67;
  header.t.write_reply.transaction_identifier = 0x0000;

  EXPECT_EQ(
      rmap_header_serialize(&serialized_size, data, sizeof(data), &header),
      RMAP_OK);
}

TEST(RmapHeaderSerialize, SendReadReplyNotEnoughSpace)
{
  size_t serialized_size;
  rmap_send_header_t header;
  unsigned char data[64];

  const uint8_t reply_address[] = { 0x1 };

  header.type = RMAP_TYPE_READ_REPLY;
  header.t.read_reply.reply_address.length = sizeof(reply_address);
  memcpy(
    header.t.read_reply.reply_address.data,
    reply_address,
    sizeof(reply_address));
  header.t.read_reply.initiator_logical_address = 0xFE;
  header.t.read_reply.command_codes = RMAP_COMMAND_CODE_REPLY;
  header.t.read_reply.status = 0x00;
  header.t.read_reply.target_logical_address = 0x67;
  header.t.read_reply.transaction_identifier = 0x0000;
  header.t.read_reply.data_length = 0x10;

  /* Read reply header is reply address plus 12 bytes fixed header. */
  const size_t one_less_than_needed_size = sizeof(reply_address) + 12 - 1;
  EXPECT_EQ(
      rmap_header_serialize(
        &serialized_size,
        data,
        one_less_than_needed_size,
        &header),
      RMAP_NOT_ENOUGH_SPACE);
}

TEST(RmapHeaderSerialize, SendReadReplyExactlyEnoughSpace)
{
  size_t serialized_size;
  rmap_send_header_t header;
  unsigned char data[64];

  const uint8_t reply_address[] = { 0x1 };

  header.type = RMAP_TYPE_READ_REPLY;
  header.t.read_reply.reply_address.length = sizeof(reply_address);
  memcpy(
    header.t.read_reply.reply_address.data,
    reply_address,
    sizeof(reply_address));
  header.t.read_reply.initiator_logical_address = 0xFE;
  header.t.read_reply.command_codes = RMAP_COMMAND_CODE_REPLY;
  header.t.read_reply.status = 0x00;
  header.t.read_reply.target_logical_address = 0x67;
  header.t.read_reply.transaction_identifier = 0x0000;
  header.t.read_reply.data_length = 0x10;

  /* Read reply header is reply address plus 12 bytes fixed header. */
  const size_t exactly_needed_size = sizeof(reply_address) + 12;
  EXPECT_EQ(
      rmap_header_serialize(
        &serialized_size,
        data,
        exactly_needed_size,
        &header),
      RMAP_OK);
}

TEST(RmapHeaderSerialize, SendReadReplyReplyAddressTooLong)
{
  size_t serialized_size;
  rmap_send_header_t header;
  unsigned char data[64];

  const uint8_t maximum_reply_address[] = {
    0x1, 0x2, 0x3, 0x4,
    0x5, 0x6, 0x7, 0x8,
    0x9, 0xA, 0xB, 0xC
  };

  header.type = RMAP_TYPE_READ_REPLY;
  header.t.read_reply.reply_address.length = sizeof(maximum_reply_address) + 1;
  memcpy(
    header.t.read_reply.reply_address.data,
    maximum_reply_address,
    sizeof(maximum_reply_address));
  header.t.read_reply.initiator_logical_address = 0xFE;
  header.t.read_reply.command_codes = RMAP_COMMAND_CODE_REPLY;
  header.t.read_reply.status = 0x00;
  header.t.read_reply.target_logical_address = 0x67;
  header.t.read_reply.transaction_identifier = 0x0000;
  header.t.read_reply.data_length = 0x10;

  EXPECT_EQ(
      rmap_header_serialize(&serialized_size, data, sizeof(data), &header),
      RMAP_REPLY_ADDRESS_TOO_LONG);
}

TEST(RmapHeaderSerialize, SendReadReplyMaximumReplyAddressLength)
{
  size_t serialized_size;
  rmap_send_header_t header;
  unsigned char data[64];

  const uint8_t maximum_reply_address[] = {
    0x1, 0x2, 0x3, 0x4,
    0x5, 0x6, 0x7, 0x8,
    0x9, 0xA, 0xB, 0xC
  };

  header.type = RMAP_TYPE_READ_REPLY;
  header.t.read_reply.reply_address.length = sizeof(maximum_reply_address);
  memcpy(
    header.t.read_reply.reply_address.data,
    maximum_reply_address,
    sizeof(maximum_reply_address));
  header.t.read_reply.initiator_logical_address = 0xFE;
  header.t.read_reply.command_codes = RMAP_COMMAND_CODE_REPLY;
  header.t.read_reply.status = 0x00;
  header.t.read_reply.target_logical_address = 0x67;
  header.t.read_reply.transaction_identifier = 0x0000;
  header.t.read_reply.data_length = 0x10;

  EXPECT_EQ(
      rmap_header_serialize(&serialized_size, data, sizeof(data), &header),
      RMAP_OK);
}

TEST(RmapHeaderSerialize, SendReadReplyDataLengthTooBig)
{
  size_t serialized_size;
  rmap_send_header_t header;
  unsigned char data[64];

  const uint8_t reply_address[] = { 0x1 };

  header.type = RMAP_TYPE_READ_REPLY;
  header.t.read_reply.reply_address.length = sizeof(reply_address);
  memcpy(
    header.t.read_reply.reply_address.data,
    reply_address,
    sizeof(reply_address));
  header.t.read_reply.initiator_logical_address = 0xFE;
  header.t.read_reply.command_codes = RMAP_COMMAND_CODE_REPLY;
  header.t.read_reply.status = 0x00;
  header.t.read_reply.target_logical_address = 0x67;
  header.t.read_reply.transaction_identifier = 0x0000;
  header.t.read_reply.data_length = 1 << 24;

  EXPECT_EQ(
      rmap_header_serialize(
        &serialized_size,
        data,
        sizeof(data),
        &header),
      RMAP_DATA_LENGTH_TOO_BIG);
}

TEST(RmapHeaderSerialize, SendReadReplyMaximumDataLength)
{
  size_t serialized_size;
  rmap_send_header_t header;
  unsigned char data[64];

  const uint8_t reply_address[] = { 0x1 };

  header.type = RMAP_TYPE_READ_REPLY;
  header.t.read_reply.reply_address.length = sizeof(reply_address);
  memcpy(
    header.t.read_reply.reply_address.data,
    reply_address,
    sizeof(reply_address));
  header.t.read_reply.initiator_logical_address = 0xFE;
  header.t.read_reply.command_codes = RMAP_COMMAND_CODE_REPLY;
  header.t.read_reply.status = 0x00;
  header.t.read_reply.target_logical_address = 0x67;
  header.t.read_reply.transaction_identifier = 0x0000;
  header.t.read_reply.data_length = (1 << 24) - 1;

  EXPECT_EQ(
      rmap_header_serialize(
        &serialized_size,
        data,
        sizeof(data),
        &header),
      RMAP_OK);
}

TEST(RmapHeaderSerialize, TestPattern0Command)
{
  size_t serialized_size;
  rmap_send_header_t header;
  unsigned char data[64];

  header.type = RMAP_TYPE_COMMAND;
  header.t.command.target_address.length = 0;
  header.t.command.target_logical_address = 0xFE;
  header.t.command.reply_address.length = 0;
  header.t.command.key = 0x00;
  header.t.command.initiator_logical_address = 0x67;
  header.t.command.command_codes =
    RMAP_COMMAND_CODE_WRITE |
    RMAP_COMMAND_CODE_INCREMENT |
    RMAP_COMMAND_CODE_REPLY;
  header.t.command.transaction_identifier = 0x0000;
  header.t.command.extended_address = 0x00;
  header.t.command.address = 0xA0000000;
  header.t.command.data_length = 0x000010;

  ASSERT_EQ(
      rmap_header_serialize(
        &serialized_size,
        data,
        sizeof(data),
        &header),
      RMAP_OK);

  EXPECT_THAT(
      std::vector<unsigned char>(data, data + serialized_size),
      testing::ElementsAreArray(
        test_pattern0_unverified_incrementing_write_with_reply,
        serialized_size));
}

TEST(RmapHeaderSerialize, TestPattern0Reply)
{
  size_t serialized_size;
  rmap_send_header_t header;
  unsigned char data[64];

  header.type = RMAP_TYPE_WRITE_REPLY;
  header.t.write_reply.reply_address.length = 0;
  header.t.write_reply.initiator_logical_address = 0x67;
  header.t.write_reply.command_codes =
    RMAP_COMMAND_CODE_WRITE |
    RMAP_COMMAND_CODE_INCREMENT |
    RMAP_COMMAND_CODE_REPLY;
  header.t.write_reply.status = 0;
  header.t.write_reply.target_logical_address = 0xFE;
  header.t.write_reply.transaction_identifier = 0x0000;

  ASSERT_EQ(
      rmap_header_serialize(
        &serialized_size,
        data,
        sizeof(data),
        &header),
      RMAP_OK);

  EXPECT_THAT(
      std::vector<unsigned char>(data, data + serialized_size),
      testing::ElementsAreArray(
        test_pattern0_expected_write_reply,
        serialized_size));
}

TEST(RmapHeaderSerialize, TestPattern1Command)
{
  size_t serialized_size;
  rmap_send_header_t header;
  unsigned char data[64];

  header.type = RMAP_TYPE_COMMAND;
  header.t.command.target_address.length = 0;
  header.t.command.target_logical_address = 0xFE;
  header.t.command.reply_address.length = 0;
  header.t.command.key = 0x00;
  header.t.command.initiator_logical_address = 0x67;
  header.t.command.command_codes =
    RMAP_COMMAND_CODE_INCREMENT |
    RMAP_COMMAND_CODE_REPLY;
  header.t.command.transaction_identifier = 0x0001;
  header.t.command.extended_address = 0x00;
  header.t.command.address = 0xA0000000;
  header.t.command.data_length = 0x000010;

  ASSERT_EQ(
      rmap_header_serialize(
        &serialized_size,
        data,
        sizeof(data),
        &header),
      RMAP_OK);

  EXPECT_THAT(
      std::vector<unsigned char>(data, data + serialized_size),
      testing::ElementsAreArray(
        test_pattern1_incrementing_read,
        serialized_size));
}

TEST(RmapHeaderSerialize, TestPattern1Reply)
{
  size_t serialized_size;
  rmap_send_header_t header;
  unsigned char data[64];

  header.type = RMAP_TYPE_READ_REPLY;
  header.t.read_reply.reply_address.length = 0;
  header.t.read_reply.initiator_logical_address = 0x67;
  header.t.read_reply.command_codes =
    RMAP_COMMAND_CODE_INCREMENT |
    RMAP_COMMAND_CODE_REPLY;
  header.t.read_reply.status = 0;
  header.t.read_reply.target_logical_address = 0xFE;
  header.t.read_reply.transaction_identifier = 0x0001;
  header.t.read_reply.data_length = 0x000010;

  ASSERT_EQ(
      rmap_header_serialize(
        &serialized_size,
        data,
        sizeof(data),
        &header),
      RMAP_OK);

  EXPECT_THAT(
      std::vector<unsigned char>(data, data + serialized_size),
      testing::ElementsAreArray(
        test_pattern1_expected_read_reply,
        serialized_size));
}

TEST(RmapHeaderSerialize, TestPattern2Command)
{
  size_t serialized_size;
  rmap_send_header_t header;
  unsigned char data[64];

  const uint8_t target_address[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };

  header.type = RMAP_TYPE_COMMAND;
  header.t.command.target_address.data = target_address;
  header.t.command.target_address.length = sizeof(target_address);
  header.t.command.target_logical_address = 0xFE;
  header.t.command.reply_address.data[0] = 0x00;
  header.t.command.reply_address.data[1] = 0x99;
  header.t.command.reply_address.data[2] = 0xAA;
  header.t.command.reply_address.data[3] = 0xBB;
  header.t.command.reply_address.data[4] = 0xCC;
  header.t.command.reply_address.data[5] = 0xDD;
  header.t.command.reply_address.data[6] = 0xEE;
  header.t.command.reply_address.data[7] = 0x00;
  header.t.command.reply_address.length = 8;
  header.t.command.key = 0x00;
  header.t.command.initiator_logical_address = 0x67;
  header.t.command.command_codes =
    RMAP_COMMAND_CODE_WRITE |
    RMAP_COMMAND_CODE_INCREMENT |
    RMAP_COMMAND_CODE_REPLY;
  header.t.command.transaction_identifier = 0x0002;
  header.t.command.extended_address = 0x00;
  header.t.command.address = 0xA0000010;
  header.t.command.data_length = 0x000010;

  ASSERT_EQ(
      rmap_header_serialize(
        &serialized_size,
        data,
        sizeof(data),
        &header),
      RMAP_OK);

  EXPECT_THAT(
      std::vector<unsigned char>(data, data + serialized_size),
      testing::ElementsAreArray(
        test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses,
        serialized_size));
}

TEST(RmapHeaderSerialize, TestPattern2Reply)
{
  size_t serialized_size;
  rmap_send_header_t header;
  unsigned char data[64];

  header.type = RMAP_TYPE_WRITE_REPLY;
  header.t.write_reply.reply_address.data[0] = 0x00;
  header.t.write_reply.reply_address.data[1] = 0x99;
  header.t.write_reply.reply_address.data[2] = 0xAA;
  header.t.write_reply.reply_address.data[3] = 0xBB;
  header.t.write_reply.reply_address.data[4] = 0xCC;
  header.t.write_reply.reply_address.data[5] = 0xDD;
  header.t.write_reply.reply_address.data[6] = 0xEE;
  header.t.write_reply.reply_address.data[7] = 0x00;
  header.t.write_reply.reply_address.length = 8;
  header.t.write_reply.initiator_logical_address = 0x67;
  header.t.write_reply.command_codes =
    RMAP_COMMAND_CODE_WRITE |
    RMAP_COMMAND_CODE_INCREMENT |
    RMAP_COMMAND_CODE_REPLY;
  header.t.write_reply.status = 0;
  header.t.write_reply.target_logical_address = 0xFE;
  header.t.write_reply.transaction_identifier = 0x0002;

  ASSERT_EQ(
      rmap_header_serialize(
        &serialized_size,
        data,
        sizeof(data),
        &header),
      RMAP_OK);

  EXPECT_THAT(
      std::vector<unsigned char>(data, data + serialized_size),
      testing::ElementsAreArray(
        test_pattern2_expected_write_reply_with_spacewire_addresses,
        serialized_size));
}

TEST(RmapHeaderSerialize, TestPattern3Command)
{
  size_t serialized_size;
  rmap_send_header_t header;
  unsigned char data[64];

  const uint8_t target_address[] = { 0x11, 0x22, 0x33, 0x44 };

  header.type = RMAP_TYPE_COMMAND;
  header.t.command.target_address.data = target_address;
  header.t.command.target_address.length = sizeof(target_address);
  header.t.command.target_logical_address = 0xFE;
  header.t.command.reply_address.data[0] = 0x99;
  header.t.command.reply_address.data[1] = 0xAA;
  header.t.command.reply_address.data[2] = 0xBB;
  header.t.command.reply_address.data[3] = 0xCC;
  header.t.command.reply_address.length = 4;
  header.t.command.key = 0x00;
  header.t.command.initiator_logical_address = 0x67;
  header.t.command.command_codes =
    RMAP_COMMAND_CODE_INCREMENT |
    RMAP_COMMAND_CODE_REPLY;
  header.t.command.transaction_identifier = 0x0003;
  header.t.command.extended_address = 0x00;
  header.t.command.address = 0xA0000010;
  header.t.command.data_length = 0x000010;

  ASSERT_EQ(
      rmap_header_serialize(
        &serialized_size,
        data,
        sizeof(data),
        &header),
      RMAP_OK);

  EXPECT_THAT(
      std::vector<unsigned char>(data, data + serialized_size),
      testing::ElementsAreArray(
        test_pattern3_incrementing_read_with_spacewire_addresses,
        serialized_size));
}

TEST(RmapHeaderSerialize, TestPattern3Reply)
{
  size_t serialized_size;
  rmap_send_header_t header;
  unsigned char data[64];

  header.type = RMAP_TYPE_READ_REPLY;
  header.t.read_reply.reply_address.data[0] = 0x99;
  header.t.read_reply.reply_address.data[1] = 0xAA;
  header.t.read_reply.reply_address.data[2] = 0xBB;
  header.t.read_reply.reply_address.data[3] = 0xCC;
  header.t.read_reply.reply_address.length = 4;
  header.t.read_reply.initiator_logical_address = 0x67;
  header.t.read_reply.command_codes =
    RMAP_COMMAND_CODE_INCREMENT |
    RMAP_COMMAND_CODE_REPLY;
  header.t.read_reply.status = 0;
  header.t.read_reply.target_logical_address = 0xFE;
  header.t.read_reply.transaction_identifier = 0x0003;
  header.t.read_reply.data_length = 0x000010;

  ASSERT_EQ(
      rmap_header_serialize(
        &serialized_size,
        data,
        sizeof(data),
        &header),
      RMAP_OK);

  EXPECT_THAT(
      std::vector<unsigned char>(data, data + serialized_size),
      testing::ElementsAreArray(
        test_pattern3_expected_read_reply_with_spacewire_addresses,
        serialized_size));
}

TEST(RmapHeaderInitializeReply, Nullptr)
{
  rmap_send_header_t reply;
  rmap_receive_header_t receive_header;
  size_t serialized_size;

  EXPECT_EQ(rmap_header_initialize_reply(NULL, NULL), RMAP_NULLPTR);
  EXPECT_EQ(rmap_header_initialize_reply(&reply, NULL), RMAP_NULLPTR);

  ASSERT_EQ(
      rmap_header_deserialize(
        &serialized_size,
        &receive_header,
        (unsigned char *)test_pattern0_unverified_incrementing_write_with_reply,
        sizeof(test_pattern0_unverified_incrementing_write_with_reply)),
      RMAP_OK);
  ASSERT_EQ(receive_header.type, RMAP_TYPE_COMMAND);
  EXPECT_EQ(
      rmap_header_initialize_reply(NULL, &receive_header.t.command),
      RMAP_NULLPTR);
}

TEST(RmapHeaderInitializeReply, NoReply)
{
  rmap_send_header_t reply;
  rmap_receive_header_t receive_header;
  size_t serialized_size;

  ASSERT_EQ(
      rmap_header_deserialize(
        &serialized_size,
        &receive_header,
        (unsigned char *)test_pattern0_unverified_incrementing_write_with_reply,
        sizeof(test_pattern0_unverified_incrementing_write_with_reply)),
      RMAP_OK);
  ASSERT_EQ(receive_header.type, RMAP_TYPE_COMMAND);
  receive_header.t.command.command_codes &= ~RMAP_COMMAND_CODE_REPLY;
  EXPECT_EQ(
      rmap_header_initialize_reply(&reply, &receive_header.t.command),
      RMAP_NO_REPLY);

  ASSERT_EQ(
      rmap_header_deserialize(
        &serialized_size,
        &receive_header,
        (unsigned char *)test_pattern1_incrementing_read,
        sizeof(test_pattern1_incrementing_read)),
      RMAP_OK);
  ASSERT_EQ(receive_header.type, RMAP_TYPE_COMMAND);
  receive_header.t.command.command_codes &= ~RMAP_COMMAND_CODE_REPLY;
  EXPECT_EQ(
      rmap_header_initialize_reply(&reply, &receive_header.t.command),
      RMAP_NO_REPLY);
}

TEST(RmapHeaderInitializeReply, TestPattern0)
{
  rmap_send_header_t reply;
  rmap_receive_header_t receive_header;
  size_t serialized_size;

  rmap_receive_command_header_t *const cmd = &receive_header.t.command;

  ASSERT_EQ(
      rmap_header_deserialize(
        &serialized_size,
        &receive_header,
        (unsigned char *)test_pattern0_unverified_incrementing_write_with_reply,
        sizeof(test_pattern0_unverified_incrementing_write_with_reply)),
      RMAP_OK);
  ASSERT_EQ(receive_header.type, RMAP_TYPE_COMMAND);
  EXPECT_EQ(rmap_header_initialize_reply(&reply, cmd), RMAP_OK);

  ASSERT_EQ(reply.type, RMAP_TYPE_WRITE_REPLY);

  rmap_send_write_reply_header_t *const r = &reply.t.write_reply;

  EXPECT_EQ(r->reply_address.length, cmd->reply_address.length);
  EXPECT_EQ(
      std::vector<unsigned char>(
        r->reply_address.data,
        r->reply_address.data + r->reply_address.length),
      std::vector<unsigned char>(
        cmd->reply_address.data,
        cmd->reply_address.data + cmd->reply_address.length));
  EXPECT_EQ(r->initiator_logical_address, cmd->initiator_logical_address);
  EXPECT_EQ(r->command_codes, cmd->command_codes);
  EXPECT_EQ(r->status, 0);
  EXPECT_EQ(r->target_logical_address, cmd->target_logical_address);
  EXPECT_EQ(r->transaction_identifier, cmd->transaction_identifier);
}

TEST(RmapHeaderInitializeReply, TestPattern1)
{
  rmap_send_header_t reply;
  rmap_receive_header_t receive_header;
  size_t serialized_size;

  rmap_receive_command_header_t *const cmd = &receive_header.t.command;

  ASSERT_EQ(
      rmap_header_deserialize(
        &serialized_size,
        &receive_header,
        (unsigned char *)test_pattern1_incrementing_read,
        sizeof(test_pattern1_incrementing_read)),
      RMAP_OK);
  ASSERT_EQ(receive_header.type, RMAP_TYPE_COMMAND);
  EXPECT_EQ(rmap_header_initialize_reply(&reply, cmd), RMAP_OK);

  ASSERT_EQ(reply.type, RMAP_TYPE_READ_REPLY);

  rmap_send_read_reply_header_t *const r = &reply.t.read_reply;

  EXPECT_EQ(r->reply_address.length, cmd->reply_address.length);
  EXPECT_EQ(
      std::vector<unsigned char>(
        r->reply_address.data,
        r->reply_address.data + r->reply_address.length),
      std::vector<unsigned char>(
        cmd->reply_address.data,
        cmd->reply_address.data + cmd->reply_address.length));
  EXPECT_EQ(r->initiator_logical_address, cmd->initiator_logical_address);
  EXPECT_EQ(r->command_codes, cmd->command_codes);
  EXPECT_EQ(r->status, 0);
  EXPECT_EQ(r->target_logical_address, cmd->target_logical_address);
  EXPECT_EQ(r->transaction_identifier, cmd->transaction_identifier);
  EXPECT_EQ(r->data_length, cmd->data_length);
}

TEST(RmapHeaderInitializeReply, TestPattern2)
{
  rmap_send_header_t reply;
  rmap_receive_header_t receive_header;
  size_t serialized_size;

  rmap_receive_command_header_t *const cmd = &receive_header.t.command;

  ASSERT_EQ(
      rmap_header_deserialize(
        &serialized_size,
        &receive_header,
        (unsigned char *)test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses +
        test_pattern2_target_address_length,
        sizeof(test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses) -
        test_pattern2_target_address_length),
      RMAP_OK);
  ASSERT_EQ(receive_header.type, RMAP_TYPE_COMMAND);
  EXPECT_EQ(rmap_header_initialize_reply(&reply, cmd), RMAP_OK);

  ASSERT_EQ(reply.type, RMAP_TYPE_WRITE_REPLY);

  rmap_send_write_reply_header_t *const r = &reply.t.write_reply;

  EXPECT_EQ(r->reply_address.length, cmd->reply_address.length);
  EXPECT_EQ(
      std::vector<unsigned char>(
        r->reply_address.data,
        r->reply_address.data + r->reply_address.length),
      std::vector<unsigned char>(
        cmd->reply_address.data,
        cmd->reply_address.data + cmd->reply_address.length));
  EXPECT_EQ(r->initiator_logical_address, cmd->initiator_logical_address);
  EXPECT_EQ(r->command_codes, cmd->command_codes);
  EXPECT_EQ(r->status, 0);
  EXPECT_EQ(r->target_logical_address, cmd->target_logical_address);
  EXPECT_EQ(r->transaction_identifier, cmd->transaction_identifier);
}

TEST(RmapHeaderInitializeReply, TestPattern3)
{
  rmap_send_header_t reply;
  rmap_receive_header_t receive_header;
  size_t serialized_size;

  rmap_receive_command_header_t *const cmd = &receive_header.t.command;

  ASSERT_EQ(
      rmap_header_deserialize(
        &serialized_size,
        &receive_header,
        (unsigned char *)test_pattern3_incrementing_read_with_spacewire_addresses +
        test_pattern3_target_address_length,
        sizeof(test_pattern3_incrementing_read_with_spacewire_addresses) -
        test_pattern3_target_address_length),
      RMAP_OK);
  ASSERT_EQ(receive_header.type, RMAP_TYPE_COMMAND);
  EXPECT_EQ(rmap_header_initialize_reply(&reply, cmd), RMAP_OK);

  ASSERT_EQ(reply.type, RMAP_TYPE_READ_REPLY);

  rmap_send_read_reply_header_t *const r = &reply.t.read_reply;

  EXPECT_EQ(r->reply_address.length, cmd->reply_address.length);
  EXPECT_EQ(
      std::vector<unsigned char>(
        r->reply_address.data,
        r->reply_address.data + r->reply_address.length),
      std::vector<unsigned char>(
        cmd->reply_address.data,
        cmd->reply_address.data + cmd->reply_address.length));
  EXPECT_EQ(r->initiator_logical_address, cmd->initiator_logical_address);
  EXPECT_EQ(r->command_codes, cmd->command_codes);
  EXPECT_EQ(r->status, 0);
  EXPECT_EQ(r->target_logical_address, cmd->target_logical_address);
  EXPECT_EQ(r->transaction_identifier, cmd->transaction_identifier);
  EXPECT_EQ(r->data_length, cmd->data_length);
}
