/** Examples showing creation of RMAP read replies from read commands.
 *
 * These examples shows how RMAP read replies can be created from source RMAP
 * read commands using the spacewire-rmap library functions.
 *
 * Separate examples are provided for:
 * * Data added after creating the RMAP reply.
 * * Data added before creating the RMAP reply.
 *
 * The created RMAP read replies corresponds to the RMAP CRC test pattern
 * named "Expected RMAP successful read reply to the previous command ‐ with
 * SpaceWire addresses" from section A.4 in the RMAP standard (ECSS‐E‐ST‐50‐52C
 * 5 February 2010).
 */

#include "rmap.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

void create_a_read_reply_from_a_command(void)
{
  enum rmap_status status;
  uint8_t buf[64];
  size_t reply_header_offset;

  const uint8_t read_command[] = {
    0xFE, 0x01, 0x4D, 0x00, 0x99, 0xAA, 0xBB, 0xCC, 0x67, 0x00, 0x03, 0x00,
    0xA0, 0x00, 0x00, 0x10, 0x00, 0x00, 0x10, 0xF7,
  };

  status = rmap_create_success_reply_from_command(
      buf,
      &reply_header_offset,
      sizeof(buf),
      read_command);
  if (status != RMAP_OK) {
    printf("Failed to create reply: %s\n", rmap_status_text(status));
    return;
  }

  uint8_t *const header = buf + reply_header_offset;

  const uint8_t data[] = {
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB,
    0xAC, 0xAD, 0xAE, 0xAF,
  };
  const size_t header_size = rmap_calculate_header_size(header);
  memcpy(header + header_size, data, sizeof(data));
  header[header_size + sizeof(data)] =
    rmap_crc_calculate(header + header_size, sizeof(data));

  rmap_set_status(header, RMAP_STATUS_FIELD_CODE_SUCCESS);
  rmap_set_data_length(header, sizeof(data));
  rmap_calculate_and_set_header_crc(header);

  const size_t packet_size =
    reply_header_offset + header_size + sizeof(data) + 1;

  printf("RMAP read reply packet with size %zu:\n", packet_size);
  for (size_t i = 0; i < packet_size; ++i) {
      printf("%02X", buf[i]);
    if (i < packet_size) {
      printf(" ");
    }
  }
  printf("\n");
}

void create_a_read_reply_from_a_command_with_data_added_before(void)
{
  enum rmap_status status;
  uint8_t buf[64];
  size_t reply_offset;
  size_t reply_header_offset;

  const uint8_t read_command[] = {
    0xFE, 0x01, 0x4D, 0x00, 0x99, 0xAA, 0xBB, 0xCC, 0x67, 0x00, 0x03, 0x00,
    0xA0, 0x00, 0x00, 0x10, 0x00, 0x00, 0x10, 0xF7,
  };

  const size_t data_offset =
    RMAP_REPLY_ADDRESS_LENGTH_MAX + RMAP_HEADER_SIZE_MAX;
  const uint8_t data[] = {
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB,
    0xAC, 0xAD, 0xAE, 0xAF,
  };
  memcpy(buf + data_offset, data, sizeof(data));
  buf[data_offset + sizeof(data)] =
    rmap_crc_calculate(buf + data_offset, sizeof(data));

  status = rmap_create_success_reply_from_command_before(
      buf,
      &reply_offset,
      &reply_header_offset,
      data_offset,
      read_command);
  if (status != RMAP_OK) {
    printf("Failed to create reply: %s\n", rmap_status_text(status));
    return;
  }

  uint8_t *const header = buf + reply_header_offset;

  rmap_set_status(header, RMAP_STATUS_FIELD_CODE_SUCCESS);
  rmap_set_data_length(header, sizeof(data));
  rmap_calculate_and_set_header_crc(header);

  const size_t packet_size = data_offset + sizeof(data) + 1 - reply_offset;

  printf("RMAP read reply packet with size %zu:\n", packet_size);
  for (size_t i = 0; i < packet_size; ++i) {
      printf("%02X", buf[reply_offset + i]);
    if (i < packet_size) {
      printf(" ");
    }
  }
  printf("\n");
}

int main(void)
{
  create_a_read_reply_from_a_command();
  create_a_read_reply_from_a_command_with_data_added_before();
}
