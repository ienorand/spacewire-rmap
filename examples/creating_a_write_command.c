/** Examples showing creation of RMAP write commands.
 *
 * These examples shows how RMAP read replies can be created from source RMAP
 * read commands using the spacewire-rmap library functions.
 *
 * Separate examples are provided for:
 * * Data added after creating the RMAP command.
 * * Data added before creating the RMAP command.
 *
 * The created RMAP write commands corresponds to the RMAP CRC test pattern
 * named "RMAP non‐verified incrementing write‐with‐reply command ‐ with
 * SpaceWire addresses" from section A.4 in the RMAP standard (ECSS‐E‐ST‐50‐52C
 * 5 February 2010).
 */

#include "rmap.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

void create_a_write_command(void)
{
  uint8_t buf[64];
  enum rmap_status status;

  const uint8_t target_address[] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77
  };
  memcpy(buf, target_address, sizeof(target_address));

  const uint8_t reply_address[] = { 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x00 };

  uint8_t *const header = buf + sizeof(target_address);
  status = rmap_initialize_header(
      header,
      sizeof(buf) - sizeof(target_address),
      RMAP_PACKET_TYPE_COMMAND,
      RMAP_COMMAND_CODE_WRITE |
      RMAP_COMMAND_CODE_REPLY |
      RMAP_COMMAND_CODE_INCREMENT,
      sizeof(reply_address));
  if (status != RMAP_OK) {
    printf("Failed to create write command: %s\n", rmap_status_text(status));
    return;
  }

  rmap_set_target_logical_address(header, 0xFE);
  rmap_set_key(header, 0x00);
  rmap_set_reply_address(header, reply_address, sizeof(reply_address));
  rmap_set_initiator_logical_address(header, 0x67);
  rmap_set_transaction_identifier(header, 2);
  rmap_set_extended_address(header, 0x00);
  rmap_set_address(header, 0xA0000010);
  rmap_set_data_length(header, 16);
  rmap_calculate_and_set_header_crc(header);

  const size_t header_size = rmap_calculate_header_size(header);

  const uint8_t data[] = {
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB,
    0xAC, 0xAD, 0xAE, 0xAF,
  };
  memcpy(header + header_size, data, sizeof(data));
  header[header_size + sizeof(data)] =
    rmap_crc_calculate(header + header_size, sizeof(data));

  const size_t packet_size =
    sizeof(target_address) + header_size + sizeof(data) + 1;

  printf("RMAP write command packet with size %zu:\n", packet_size);
  for (size_t i = 0; i < packet_size; ++i) {
      printf("%02X", buf[i]);
    if (i < packet_size) {
      printf(" ");
    }
  }
  printf("\n");
}

void create_a_write_command_with_data_added_before(void)
{
  uint8_t buf[64];
  enum rmap_status status;
  size_t header_offset;

  const uint8_t target_address[] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77
  };

  const size_t data_offset = sizeof(target_address) + RMAP_HEADER_SIZE_MAX;
  const uint8_t data[] = {
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB,
    0xAC, 0xAD, 0xAE, 0xAF,
  };
  memcpy(buf + data_offset, data, sizeof(data));
  buf[data_offset + sizeof(data)] =
    rmap_crc_calculate(buf + data_offset, sizeof(data));

  const uint8_t reply_address[] = { 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x00 };

  status = rmap_initialize_header_before(
      &header_offset,
      buf,
      data_offset,
      RMAP_PACKET_TYPE_COMMAND,
      RMAP_COMMAND_CODE_WRITE |
      RMAP_COMMAND_CODE_REPLY |
      RMAP_COMMAND_CODE_INCREMENT,
      sizeof(reply_address));
  if (status != RMAP_OK) {
    printf("Failed to create write command: %s\n", rmap_status_text(status));
    return;
  }

  uint8_t *const header = buf + header_offset;

  rmap_set_target_logical_address(header, 0xFE);
  rmap_set_key(header, 0x00);
  rmap_set_reply_address(header, reply_address, sizeof(reply_address));
  rmap_set_initiator_logical_address(header, 0x67);
  rmap_set_transaction_identifier(header, 2);
  rmap_set_extended_address(header, 0x00);
  rmap_set_address(header, 0xA0000010);
  rmap_set_data_length(header, 16);
  rmap_calculate_and_set_header_crc(header);

  memcpy(
      buf + header_offset - sizeof(target_address),
      target_address,
      sizeof(target_address));

  const size_t packet_size =
    data_offset + sizeof(data) + 1 + sizeof(target_address) - header_offset;

  printf("RMAP write command packet with size %zu:\n", packet_size);
  for (size_t i = 0; i < packet_size; ++i) {
      printf("%02X", buf[header_offset - sizeof(target_address) + i]);
    if (i < packet_size) {
      printf(" ");
    }
  }
  printf("\n");
}

int main(void)
{
  create_a_write_command();
  create_a_write_command_with_data_added_before();
}
