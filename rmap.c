#include "rmap.h"

#include <assert.h>
#include <string.h>
#include <stdbool.h>

#define RMAP_REPLY_ADDRESS_LENGTH_MAX 12
#define RMAP_DATA_LENGTH_MAX ((1 << 24) - 1)

#define RMAP_COMMAND_HEADER_STATIC_SIZE 16
#define RMAP_WRITE_REPLY_HEADER_STATIC_SIZE 8
#define RMAP_READ_REPLY_HEADER_STATIC_SIZE 12

#define RMAP_INSTRUCTION_PACKET_TYPE_SHIFT 6
#define RMAP_INSTRUCTION_PACKET_TYPE_MASK \
  (3 << RMAP_INSTRUCTION_PACKET_TYPE_SHIFT)

#define RMAP_INSTRUCTION_COMMAND_WRITE_SHIFT 5
#define RMAP_INSTRUCTION_COMMAND_WRITE_MASK \
  (1 << RMAP_INSTRUCTION_COMMAND_WRITE_SHIFT)

#define RMAP_INSTRUCTION_COMMAND_VERIFY_SHIFT 4
#define RMAP_INSTRUCTION_COMMAND_VERIFY_MASK \
  (1 << RMAP_INSTRUCTION_COMMAND_VERIFY_SHIFT)

#define RMAP_INSTRUCTION_COMMAND_REPLY_SHIFT 3
#define RMAP_INSTRUCTION_COMMAND_REPLY_MASK \
  (1 << RMAP_INSTRUCTION_COMMAND_REPLY_SHIFT)

#define RMAP_INSTRUCTION_COMMAND_INCREMENT_SHIFT 2
#define RMAP_INSTRUCTION_COMMAND_INCREMENT_MASK \
  (1 << RMAP_INSTRUCTION_COMMAND_INCREMENT_SHIFT)

#define RMAP_INSTRUCTION_REPLY_ADDRESS_LENGTH_SHIFT 0
#define RMAP_INSTRUCTION_REPLY_ADDRESS_LENGTH_MASK \
  (3 << RMAP_INSTRUCTION_REPLY_ADDRESS_LENGTH_SHIFT)

#define RMAP_COMMAND_CODES_ALL (\
    RMAP_COMMAND_CODE_WRITE | \
    RMAP_COMMAND_CODE_VERIFY | \
    RMAP_COMMAND_CODE_REPLY | \
    RMAP_COMMAND_CODE_INCREMENT)

typedef enum {
  RMAP_PACKET_TYPE_COMMAND,
  RMAP_PACKET_TYPE_REPLY
} packet_type_t;

typedef struct {
  struct {
    uint8_t *data;
    size_t length;
  } reply_address;
  uint8_t initiator_logical_address;
  unsigned char command_codes;
  uint8_t status;
  uint8_t target_logical_address;
  uint16_t transaction_identifier;
} common_send_reply_header_t;

typedef struct {
  struct {
    uint8_t *data;
    size_t length;
  } reply_address;
  uint8_t initiator_logical_address;
  unsigned char command_codes;
  uint8_t status;
  uint8_t target_logical_address;
  uint16_t transaction_identifier;
} common_receive_reply_header_t;

static uint8_t serialize_instruction(
    const packet_type_t packet_type,
    const unsigned char command_codes,
    const size_t reply_address_length)
{
  uint8_t instruction;

  instruction = 0;

  if (packet_type == RMAP_PACKET_TYPE_COMMAND) {
    instruction |= 1 << RMAP_INSTRUCTION_PACKET_TYPE_SHIFT;
  } else {
    assert(
        packet_type == RMAP_PACKET_TYPE_REPLY &&
        "Must be a valid packet type.");
  }

  assert(
      (command_codes & ~(RMAP_COMMAND_CODES_ALL)) == 0 &&
      "Must be a valid option.");
  if (command_codes & RMAP_COMMAND_CODE_WRITE) {
    instruction |= 1 << RMAP_INSTRUCTION_COMMAND_WRITE_SHIFT;
  }
  if (command_codes & RMAP_COMMAND_CODE_VERIFY) {
    instruction |= 1 << RMAP_INSTRUCTION_COMMAND_VERIFY_SHIFT;
  }
  if (command_codes & RMAP_COMMAND_CODE_REPLY) {
    instruction |= 1 << RMAP_INSTRUCTION_COMMAND_REPLY_SHIFT;
  }
  if (command_codes & RMAP_COMMAND_CODE_INCREMENT) {
    instruction |= 1 << RMAP_INSTRUCTION_COMMAND_INCREMENT_SHIFT;
  }

  assert(reply_address_length <= RMAP_REPLY_ADDRESS_LENGTH_MAX);
  const unsigned char reply_address_length_serialized =
    (reply_address_length + 4 - 1) / 4;
  assert(reply_address_length_serialized <= 3);
  instruction |= reply_address_length_serialized;

  return instruction;
}

static rmap_status_t deserialize_instruction(
    packet_type_t *const packet_type,
    unsigned char *const command_codes,
    size_t *const reply_address_length,
    const uint8_t instruction)
{
  packet_type_t packet_type_tmp;
  unsigned char command_codes_tmp;

  assert(packet_type);
  assert(command_codes);
  assert(reply_address_length);

  const unsigned char packet_type_representation =
    (instruction & RMAP_INSTRUCTION_PACKET_TYPE_MASK) >>
    RMAP_INSTRUCTION_PACKET_TYPE_SHIFT;
  switch (packet_type_representation) {
    case 0:
      packet_type_tmp = RMAP_PACKET_TYPE_REPLY;
      break;

    case 1:
      packet_type_tmp = RMAP_PACKET_TYPE_COMMAND;
      break;

    default:
      return RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE;
  }

  command_codes_tmp = 0;
  if ((instruction & RMAP_INSTRUCTION_COMMAND_WRITE_MASK) >>
      RMAP_INSTRUCTION_COMMAND_WRITE_SHIFT) {
    command_codes_tmp |= RMAP_COMMAND_CODE_WRITE;
  }
  if ((instruction & RMAP_INSTRUCTION_COMMAND_VERIFY_MASK) >>
      RMAP_INSTRUCTION_COMMAND_VERIFY_SHIFT) {
    command_codes_tmp |= RMAP_COMMAND_CODE_VERIFY;
  }
  if ((instruction & RMAP_INSTRUCTION_COMMAND_REPLY_MASK) >>
      RMAP_INSTRUCTION_COMMAND_REPLY_SHIFT) {
    command_codes_tmp |= RMAP_COMMAND_CODE_REPLY;
  }
  if ((instruction & RMAP_INSTRUCTION_COMMAND_INCREMENT_MASK) >>
      RMAP_INSTRUCTION_COMMAND_INCREMENT_SHIFT) {
    command_codes_tmp |= RMAP_COMMAND_CODE_INCREMENT;
  }

  switch (command_codes_tmp) {
    case 0:
    case RMAP_COMMAND_CODE_INCREMENT:
    case RMAP_COMMAND_CODE_VERIFY:
    case RMAP_COMMAND_CODE_VERIFY | RMAP_COMMAND_CODE_INCREMENT:
    case RMAP_COMMAND_CODE_VERIFY | RMAP_COMMAND_CODE_REPLY:
      /* invalid combination */
      return RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE;
  }

  const unsigned char reply_address_length_serialized =
    (instruction & RMAP_INSTRUCTION_REPLY_ADDRESS_LENGTH_MASK) >>
    RMAP_INSTRUCTION_REPLY_ADDRESS_LENGTH_SHIFT;

  *packet_type = packet_type_tmp;
  *command_codes = command_codes_tmp;
  *reply_address_length = reply_address_length_serialized * 4;

  return RMAP_OK;
}

static void make_common_from_send_write_reply_header(
    common_send_reply_header_t *const common,
    const rmap_send_write_reply_header_t *const write_reply)
{
  assert(common);
  assert(write_reply);

  /* The common reply header struct is a subset of the write reply header
   * struct ("common initial sequence" C99 (6.5.2.3/5)) hence conversion like
   * this is allowed.
   */
  const union {
    rmap_send_write_reply_header_t write_reply;
    common_send_reply_header_t common;
  } converter = { *write_reply };

  *common = converter.common;
}

static void make_common_from_send_read_reply_header(
    common_send_reply_header_t *const common,
    const rmap_send_read_reply_header_t *const read_reply)
{
  assert(common);
  assert(read_reply);

  /* The common reply header struct is a subset of the read reply header struct
   * ("common initial sequence" C99 (6.5.2.3/5)) hence conversion like this is
   * allowed.
   */
  const union {
    rmap_send_read_reply_header_t read_reply;
    common_send_reply_header_t common;
  } converter = { *read_reply };

  *common = converter.common;
}

static rmap_status_t calculate_reply_address_unpadded_size(
    size_t *const unpadded_size,
    const uint8_t *const address,
    const size_t size)
{
  size_t padding_size;

  if (!unpadded_size) {
    return RMAP_NULLPTR;
  }

  if (size == 0) {
    *unpadded_size = 0;
    return RMAP_OK;
  }

  if (!address) {
    return RMAP_NULLPTR;
  }

  if (size > RMAP_REPLY_ADDRESS_LENGTH_MAX) {
    return RMAP_REPLY_ADDRESS_TOO_LONG;
  }

  /* ignore leading zeroes in reply address field */
  padding_size = 0;
  for (size_t i = 0; i < size; ++i) {
    if (address[i] == 0) {
      ++padding_size;
    }
  }
  if (size > 0 && padding_size == size) {
    /* If reply address length is non-zero and the reply address is all zeroes,
     * the reply address used should be a single zero.
     */
    padding_size = size - 1;
  }

  *unpadded_size = size - padding_size;
  return RMAP_OK;
}

static rmap_status_t serialize_command_header(
    size_t *const serialized_size,
    unsigned char *const data,
    const size_t data_size,
    const rmap_send_command_header_t *const header)
{
  size_t calculated_serialized_size;
  unsigned char *data_ptr;

  if (!serialized_size || !data || !header) {
    return RMAP_NULLPTR;
  }
  if (header->target_address.length > 0 && !header->target_address.data) {
    return RMAP_NULLPTR;
  }
  if (header->reply_address.length > 0 && !header->reply_address.data) {
    return RMAP_NULLPTR;
  }

  const rmap_send_header_t header_wrapper = {
    RMAP_TYPE_COMMAND,
    { *header }
  };
  const rmap_status_t rmap_status =
    rmap_header_calculate_serialized_size(
        &calculated_serialized_size,
        &header_wrapper);
  if (rmap_status != RMAP_OK) {
    assert(
        rmap_status == RMAP_REPLY_ADDRESS_TOO_LONG ||
        rmap_status == RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE);
    return rmap_status;
  }

  if (calculated_serialized_size > data_size) {
    return RMAP_NOT_ENOUGH_SPACE;
  }

  if (header->data_length > RMAP_DATA_LENGTH_MAX) {
    return RMAP_DATA_LENGTH_TOO_BIG;
  }

  if (header->command_codes & ~(RMAP_COMMAND_CODES_ALL)) {
    return RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE;
  }

  data_ptr = data;

  memcpy(
      data_ptr,
      header->target_address.data,
      header->target_address.length);
  data_ptr += header->target_address.length;

  *data_ptr++ = header->target_logical_address;

  const uint8_t protocol_identifier = 1;
  *data_ptr++ = protocol_identifier;

  *data_ptr++ = serialize_instruction(
      RMAP_PACKET_TYPE_COMMAND,
      header->command_codes,
      header->reply_address.length);

  *data_ptr++ = header->key;

  const size_t reply_address_padding_size =
    calculated_serialized_size - RMAP_COMMAND_HEADER_STATIC_SIZE -
    header->target_address.length - header->reply_address.length;
  assert(reply_address_padding_size <= 3);
  memset(data_ptr, 0, reply_address_padding_size);
  data_ptr += reply_address_padding_size;
  memcpy(data_ptr, header->reply_address.data, header->reply_address.length);
  data_ptr += header->reply_address.length;

  *data_ptr++ = header->initiator_logical_address;

  *data_ptr++ = (uint8_t)(header->transaction_identifier >> 8);
  *data_ptr++ = (uint8_t)(header->transaction_identifier);

  *data_ptr++ = header->extended_address;

  *data_ptr++ = (uint8_t)(header->address >> 24);
  *data_ptr++ = (uint8_t)(header->address >> 16);
  *data_ptr++ = (uint8_t)(header->address >> 8);
  *data_ptr++ = (uint8_t)(header->address);

  *data_ptr++ = (uint8_t)(header->data_length >> 16);
  *data_ptr++ = (uint8_t)(header->data_length >> 8);
  *data_ptr++ = (uint8_t)(header->data_length);

  const unsigned char *const crc_range_start =
    data + header->target_address.length;
  const ptrdiff_t crc_range_size = data_ptr - crc_range_start;
  *data_ptr++ = rmap_crc_calculate(crc_range_start, crc_range_size);

  const ptrdiff_t size = data_ptr - data;
  assert(size >= 0);
  assert((size_t)size == calculated_serialized_size);

  *serialized_size = (size_t)size;
  return RMAP_OK;
}

static rmap_status_t serialize_common_reply_header(
    size_t *const serialized_size,
    unsigned char *const data,
    const size_t data_size,
    const common_send_reply_header_t *const header)
{
  size_t reply_address_unpadded_size;
  unsigned char *data_ptr;

  if (!serialized_size || !data || !header) {
    return RMAP_NULLPTR;
  }

  const rmap_status_t rmap_status =
    calculate_reply_address_unpadded_size(
        &reply_address_unpadded_size,
        header->reply_address.data,
        header->reply_address.length);
  if (rmap_status != RMAP_OK) {
    assert(
        rmap_status == RMAP_NULLPTR ||
        rmap_status == RMAP_REPLY_ADDRESS_TOO_LONG);
    return rmap_status;
  }

  const size_t common_header_size = reply_address_unpadded_size + 7;

  if (common_header_size > data_size) {
    return RMAP_NOT_ENOUGH_SPACE;
  }

  if (header->command_codes & ~(RMAP_COMMAND_CODES_ALL)) {
    return RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE;
  }
  if (!(header->command_codes & RMAP_COMMAND_CODE_REPLY)) {
    /* must have reply command code */
    return RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE;
  }

  data_ptr = data;

  /* Padding stripped from reply address when sending. */
  const size_t reply_address_offset =
    header->reply_address.length - reply_address_unpadded_size;
  memcpy(
      data_ptr,
      header->reply_address.data + reply_address_offset,
      reply_address_unpadded_size);
  data_ptr += reply_address_unpadded_size;

  *data_ptr++ = header->target_logical_address;

  const uint8_t protocol_identifier = 1;
  *data_ptr++ = protocol_identifier;

  *data_ptr++ = serialize_instruction(
      RMAP_PACKET_TYPE_REPLY,
      header->command_codes,
      header->reply_address.length);

  *data_ptr++ = header->status;

  *data_ptr++ = header->target_logical_address;

  *data_ptr++ = (uint8_t)(header->transaction_identifier >> 8);
  *data_ptr++ = (uint8_t)(header->transaction_identifier);

  const ptrdiff_t size = data_ptr - data;
  assert(size >= 0);
  assert((size_t)size == common_header_size);

  *serialized_size = (size_t)size;
  return RMAP_OK;
}

static rmap_status_t serialize_write_reply_header(
    size_t *const serialized_size,
    unsigned char *const data,
    const size_t data_size,
    const rmap_send_write_reply_header_t *const header)
{
  common_send_reply_header_t common_header;
  rmap_status_t rmap_status;
  size_t common_serialized_size;
  size_t reply_address_unpadded_size;

  if (!serialized_size || !header) {
    return RMAP_NULLPTR;
  }

  if (!(header->command_codes & RMAP_COMMAND_CODE_WRITE)) {
    /* must have write command code */
    return RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE;
  }

  make_common_from_send_write_reply_header(&common_header, header);

  rmap_status = serialize_common_reply_header(
      &common_serialized_size,
      data,
      data_size,
      &common_header);
  if (rmap_status != RMAP_OK) {
    assert(
        rmap_status == RMAP_NULLPTR ||
        rmap_status == RMAP_NOT_ENOUGH_SPACE ||
        rmap_status == RMAP_REPLY_ADDRESS_TOO_LONG ||
        rmap_status == RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE);
    return rmap_status;
  }

  if (data_size < common_serialized_size + 1) {
    return RMAP_NOT_ENOUGH_SPACE;
  }

  rmap_status = calculate_reply_address_unpadded_size(
      &reply_address_unpadded_size,
      header->reply_address.data,
      header->reply_address.length);
  assert(
      rmap_status == RMAP_OK &&
      "Errors should have been caught by serialize_common_reply_header().");

  const unsigned char *const crc_range_start =
    data + reply_address_unpadded_size;
  const ptrdiff_t crc_range_size =
    data + common_serialized_size - crc_range_start;
  assert(crc_range_size >= 0);
  data[common_serialized_size] =
    rmap_crc_calculate(crc_range_start, crc_range_size);

  *serialized_size = common_serialized_size + 1;
  return RMAP_OK;
}

static rmap_status_t serialize_read_reply_header(
    size_t *const serialized_size,
    unsigned char *const data,
    const size_t data_size,
    const rmap_send_read_reply_header_t *const header)
{
  common_send_reply_header_t common_header;
  rmap_status_t rmap_status;
  size_t common_serialized_size;
  size_t reply_address_unpadded_size;

  if (!serialized_size || !header) {
    return RMAP_NULLPTR;
  }

  if (header->command_codes & RMAP_COMMAND_CODE_WRITE) {
    /* must not have write command code */
    return RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE;
  }

  make_common_from_send_read_reply_header(&common_header, header);

  rmap_status = serialize_common_reply_header(
      &common_serialized_size,
      data,
      data_size,
      &common_header);
  if (rmap_status != RMAP_OK) {
    assert(
        rmap_status == RMAP_NULLPTR ||
        rmap_status == RMAP_NOT_ENOUGH_SPACE ||
        rmap_status == RMAP_REPLY_ADDRESS_TOO_LONG ||
        rmap_status == RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE);
    return rmap_status;
  }

  if (data_size < common_serialized_size + 5) {
    return RMAP_NOT_ENOUGH_SPACE;
  }

  const uint8_t reserved = 0;
  data[common_serialized_size] = reserved;

  data[common_serialized_size + 1] = (uint8_t)(header->data_length >> 16);
  data[common_serialized_size + 2] = (uint8_t)(header->data_length >> 8);
  data[common_serialized_size + 3] = (uint8_t)(header->data_length);

  rmap_status = calculate_reply_address_unpadded_size(
      &reply_address_unpadded_size,
      header->reply_address.data,
      header->reply_address.length);
  assert(
      rmap_status == RMAP_OK &&
      "Errors should have been caught by serialize_common_reply_header().");

  const unsigned char *const crc_range_start =
    data + reply_address_unpadded_size;
  const ptrdiff_t crc_range_size =
    data + common_serialized_size + 4 - crc_range_start;
  assert(crc_range_size >= 0);
  data[common_serialized_size + 4] =
    rmap_crc_calculate(crc_range_start, crc_range_size);

  *serialized_size = common_serialized_size + 5;
  return RMAP_OK;
}

rmap_status_t rmap_header_calculate_serialized_size(
    size_t *const serialized_size,
    const rmap_send_header_t *const header)
{
  common_send_reply_header_t reply_header;
  size_t reply_header_static_size;
  size_t reply_address_unpadded_size;

  if (!header || !serialized_size) {
    return RMAP_NULLPTR;
  }

  if (header->type == RMAP_TYPE_COMMAND) {
    if (header->t.command.reply_address.length >
        RMAP_REPLY_ADDRESS_LENGTH_MAX) {
      return RMAP_REPLY_ADDRESS_TOO_LONG;
    }
    const size_t reply_address_padded_length =
      (header->t.command.reply_address.length + 4 - 1) / 4 * 4;

    const size_t header_size_without_target_address =
      RMAP_COMMAND_HEADER_STATIC_SIZE + reply_address_padded_length;
    if (header->t.command.target_address.length >
        SIZE_MAX - header_size_without_target_address + 1) {
      return RMAP_NOT_ENOUGH_SPACE;
    }

    *serialized_size = header->t.command.target_address.length +
      header_size_without_target_address;

    return RMAP_OK;
  }

  if (header->type == RMAP_TYPE_WRITE_REPLY) {
    reply_header_static_size = RMAP_WRITE_REPLY_HEADER_STATIC_SIZE;
    make_common_from_send_write_reply_header(
        &reply_header,
        &header->t.write_reply);
  } else if (header->type == RMAP_TYPE_READ_REPLY) {
    reply_header_static_size = RMAP_READ_REPLY_HEADER_STATIC_SIZE;
    make_common_from_send_write_reply_header(
        &reply_header,
        &header->t.write_reply);
  } else {
    return RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE;
  }

  const rmap_status_t rmap_status =
    calculate_reply_address_unpadded_size(
        &reply_address_unpadded_size,
        reply_header.reply_address.data,
        reply_header.reply_address.length);
  if (rmap_status != RMAP_OK) {
    assert(
        rmap_status == RMAP_NULLPTR ||
        rmap_status == RMAP_REPLY_ADDRESS_TOO_LONG);
    return rmap_status;
  }

  *serialized_size = reply_address_unpadded_size + reply_header_static_size;
  return RMAP_OK;
}

rmap_status_t rmap_header_serialize(
    size_t *const serialized_size,
    unsigned char *const data,
    const size_t data_size,
    const rmap_send_header_t *const header)
{
  rmap_status_t rmap_status;
  size_t serialized_size_tmp;

  if (!header || !serialized_size) {
    return RMAP_NULLPTR;
  }

  /* Unless serialized_size_tmp is explicitly initialized before the calls to
   * serialize_write_reply_header() or serialize_read_reply_header() this will
   * generate a maybe-uninitialized compiler warning.
   *
   * This seems to be a false positive since it goes away when making all
   * non-RMAP_OK return values explicit after the call to
   * serialize_command_header(), or when testing with gcc version 7.1 or later.
   */
  serialized_size_tmp = 0;
  switch (header->type) {
    case RMAP_TYPE_COMMAND:
      rmap_status = serialize_command_header(
          &serialized_size_tmp,
          data,
          data_size,
          &header->t.command);
      break;

    case RMAP_TYPE_WRITE_REPLY:
      rmap_status = serialize_write_reply_header(
          &serialized_size_tmp,
          data,
          data_size,
          &header->t.write_reply);
      break;

    case RMAP_TYPE_READ_REPLY:
      rmap_status = serialize_read_reply_header(
          &serialized_size_tmp,
          data,
          data_size,
          &header->t.read_reply);
      break;

    default:
      return RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE;
  }

  if (rmap_status != RMAP_OK) {
    assert(
        rmap_status == RMAP_NULLPTR ||
        rmap_status == RMAP_NOT_ENOUGH_SPACE ||
        rmap_status == RMAP_REPLY_ADDRESS_TOO_LONG ||
        rmap_status == RMAP_DATA_LENGTH_TOO_BIG ||
        rmap_status == RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE);
    return rmap_status;
  }

  *serialized_size = serialized_size_tmp;
  return RMAP_OK;
}

rmap_status_t rmap_packet_serialize_inplace(
    size_t *const serialized_offset,
    size_t *const serialized_size,
    unsigned char *const data,
    const size_t data_size,
    const size_t payload_offset,
    const size_t payload_size,
    const rmap_send_header_t *const header)
{
  rmap_status_t rmap_status;
  size_t calculated_header_serialized_size;
  size_t header_serialized_size;

  if (!serialized_offset || !serialized_size || !data || !header) {
    return RMAP_NULLPTR;
  }

  if ((header->type == RMAP_TYPE_COMMAND &&
      !(header->t.command.command_codes & RMAP_COMMAND_CODE_WRITE)) ||
      header->type == RMAP_TYPE_WRITE_REPLY) {
    /* Read command and write reply does not have payload, hence are not
     * supported types. rmap_header_serialize() creates the full packet for
     * these types and should be used instead. */
    return RMAP_ECSS_TOO_MUCH_DATA;
  }

  if (payload_offset + payload_size + 1 > data_size) {
    /* no space for crc */
    return RMAP_NOT_ENOUGH_SPACE;
  }

  rmap_status = rmap_header_calculate_serialized_size(
        &calculated_header_serialized_size,
        header);
  if (rmap_status != RMAP_OK) {
    assert(
        rmap_status == RMAP_NULLPTR ||
        rmap_status == RMAP_REPLY_ADDRESS_TOO_LONG ||
        rmap_status == RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE);
    return rmap_status;
  }

  if (calculated_header_serialized_size > payload_offset) {
    return RMAP_NOT_ENOUGH_SPACE;
  }

  rmap_status = rmap_header_serialize(
      &header_serialized_size,
      data + payload_offset - calculated_header_serialized_size,
      payload_offset,
      header);
  if (rmap_status != RMAP_OK) {
    assert(
        rmap_status == RMAP_NULLPTR ||
        rmap_status == RMAP_REPLY_ADDRESS_TOO_LONG ||
        rmap_status == RMAP_DATA_LENGTH_TOO_BIG ||
        rmap_status == RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE);
    return rmap_status;
  }
  assert(header_serialized_size == calculated_header_serialized_size);

  data[payload_offset + payload_size] =
    rmap_crc_calculate(data + payload_offset, payload_size);

  *serialized_offset = payload_offset - header_serialized_size;
  *serialized_size = header_serialized_size + payload_size + 1;

  return RMAP_OK;
}

rmap_status_t rmap_header_deserialize(
    size_t *const serialized_size,
    rmap_receive_header_t *const header,
    const unsigned char *const data,
    const size_t data_size)
{
  packet_type_t packet_type;
  unsigned char command_codes;
  size_t reply_address_length;
  size_t header_size;
  rmap_type_t rmap_type;
  size_t offset;

  if (!serialized_size || !header || !data) {
    return RMAP_NULLPTR;
  }

  if (data_size < 8) {
    return RMAP_ECSS_INCOMPLETE_HEADER;
  }

  if (data[1] != 1) {
    return RMAP_NO_RMAP_PROTOCOL;
  }

  const rmap_status_t deserialize_instruction_status =
    deserialize_instruction(
        &packet_type,
        &command_codes,
        &reply_address_length,
        data[2]);
  switch (deserialize_instruction_status) {
    case RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE:
      return deserialize_instruction_status;

    default:
      assert(deserialize_instruction_status == RMAP_OK);
      break;
  }

  if (packet_type == RMAP_PACKET_TYPE_COMMAND) {
    rmap_type = RMAP_TYPE_COMMAND;
    header_size = RMAP_COMMAND_HEADER_STATIC_SIZE + reply_address_length;

    if (!(command_codes & RMAP_COMMAND_CODE_WRITE) &&
        data_size > header_size) {
      /* Data characters in read command are invalid. */
      return RMAP_ECSS_TOO_MUCH_DATA;
    }
  } else {
    if (command_codes & RMAP_COMMAND_CODE_WRITE) {
      rmap_type = RMAP_TYPE_WRITE_REPLY;
      header_size = RMAP_WRITE_REPLY_HEADER_STATIC_SIZE;
      if (data_size > header_size) {
        /* Data characters in write reply are invalid. */
        return RMAP_ECSS_TOO_MUCH_DATA;
      }
    } else {
      rmap_type = RMAP_TYPE_READ_REPLY;
      header_size = RMAP_READ_REPLY_HEADER_STATIC_SIZE;
    }
  }

  if (header_size > data_size) {
    return RMAP_ECSS_INCOMPLETE_HEADER;
  }

  const uint8_t crc = rmap_crc_calculate(data, header_size);
  /* If the recieved crc is included in the crc calculation, the result should
   * be 0.
   */
  if (crc != 0) {
    return RMAP_HEADER_CRC_ERROR;
  }

  *serialized_size = header_size;
  header->type = rmap_type;

  if (packet_type == RMAP_PACKET_TYPE_COMMAND) {
    header->t.command.target_logical_address = data[0];
    header->t.command.command_codes = command_codes;
    header->t.command.key = data[3];
    header->t.command.reply_address.data = data + 4;
    header->t.command.reply_address.length = reply_address_length;
    offset = 4 + reply_address_length;
    header->t.command.initiator_logical_address = data[offset];
    header->t.command.transaction_identifier = (uint16_t)data[offset + 1] << 8;
    header->t.command.transaction_identifier |= data[offset + 2];
    header->t.command.extended_address = data[offset + 3];
    header->t.command.address = (uint32_t)data[offset + 4] << 24;
    header->t.command.address |= (uint32_t)data[offset + 5] << 16;
    header->t.command.address |= (uint32_t)data[offset + 6] << 8;
    header->t.command.address |= (uint32_t)data[offset + 7];
    header->t.command.data_length = (uint32_t)data[offset + 8] << 16;
    header->t.command.data_length |= (uint32_t)data[offset + 9] << 8;
    header->t.command.data_length |= (uint32_t)data[offset + 10];
    return RMAP_OK;
  }

  if (command_codes & RMAP_COMMAND_CODE_WRITE) {
    header->t.write_reply.initiator_logical_address = data[0];
    header->t.write_reply.command_codes = command_codes;
    header->t.write_reply.status = data[3];
    header->t.write_reply.target_logical_address = data[4];
    header->t.write_reply.transaction_identifier = (uint16_t)data[5] << 8;
    header->t.write_reply.transaction_identifier |= data[6];
    return RMAP_OK;
  }

  header->t.read_reply.initiator_logical_address = data[0];
  header->t.read_reply.command_codes = command_codes;
  header->t.read_reply.status = data[3];
  header->t.read_reply.target_logical_address = data[4];
  header->t.read_reply.transaction_identifier = (uint16_t)data[5] << 8;
  header->t.read_reply.transaction_identifier |= data[6];
  header->t.read_reply.data_length = (uint32_t)data[8] << 16;
  header->t.read_reply.data_length |= (uint32_t)data[9] << 8;
  header->t.read_reply.data_length |= (uint32_t)data[10];
  return RMAP_OK;
}

const char *rmap_status_text(const rmap_status_t status)
{
  switch (status) {
    case RMAP_OK:
      return "RMAP_OK";

    case RMAP_NULLPTR:
      return "RMAP_NULLPTR";

    case RMAP_NOT_ENOUGH_SPACE:
      return "RMAP_NOT_ENOUGH_SPACE";

    case RMAP_REPLY_ADDRESS_TOO_LONG:
      return "RMAP_REPLY_ADDRESS_TOO_LONG";

    case RMAP_DATA_LENGTH_TOO_BIG:
      return "RMAP_DATA_LENGTH_TOO_BIG";

    case RMAP_NO_RMAP_PROTOCOL:
      return "RMAP_NO_RMAP_PROTOCOL";

    case RMAP_HEADER_CRC_ERROR:
      return "RMAP_HEADER_CRC_ERROR";

    case RMAP_ECSS_INCOMPLETE_HEADER:
      return "RMAP_ECSS_INCOMPLETE_HEADER";

    case RMAP_ECSS_ERROR_END_OF_PACKET:
      return "RMAP_ECSS_ERROR_END_OF_PACKET";

    case RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE:
      return "RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE";

    case RMAP_ECSS_TOO_MUCH_DATA:
      return "RMAP_ECSS_TOO_MUCH_DATA";

    default:
      return "INVALID_STATUS";
  }
}

uint8_t rmap_crc_calculate(
    const unsigned char *const data,
    const size_t data_size)
{
  uint8_t crc;

  static const uint8_t crc_lookup_table[] = {
    0x00, 0x91, 0xE3, 0x72, 0x07, 0x96, 0xE4, 0x75,
    0x0E, 0x9F, 0xED, 0x7C, 0x09, 0x98, 0xEA, 0x7B,
    0x1C, 0x8D, 0xFF, 0x6E, 0x1B, 0x8A, 0xF8, 0x69,
    0x12, 0x83, 0xF1, 0x60, 0x15, 0x84, 0xF6, 0x67,
    0x38, 0xA9, 0xDB, 0x4A, 0x3F, 0xAE, 0xDC, 0x4D,
    0x36, 0xA7, 0xD5, 0x44, 0x31, 0xA0, 0xD2, 0x43,
    0x24, 0xB5, 0xC7, 0x56, 0x23, 0xB2, 0xC0, 0x51,
    0x2A, 0xBB, 0xC9, 0x58, 0x2D, 0xBC, 0xCE, 0x5F,
    0x70, 0xE1, 0x93, 0x02, 0x77, 0xE6, 0x94, 0x05,
    0x7E, 0xEF, 0x9D, 0x0C, 0x79, 0xE8, 0x9A, 0x0B,
    0x6C, 0xFD, 0x8F, 0x1E, 0x6B, 0xFA, 0x88, 0x19,
    0x62, 0xF3, 0x81, 0x10, 0x65, 0xF4, 0x86, 0x17,
    0x48, 0xD9, 0xAB, 0x3A, 0x4F, 0xDE, 0xAC, 0x3D,
    0x46, 0xD7, 0xA5, 0x34, 0x41, 0xD0, 0xA2, 0x33,
    0x54, 0xC5, 0xB7, 0x26, 0x53, 0xC2, 0xB0, 0x21,
    0x5A, 0xCB, 0xB9, 0x28, 0x5D, 0xCC, 0xBE, 0x2F,
    0xE0, 0x71, 0x03, 0x92, 0xE7, 0x76, 0x04, 0x95,
    0xEE, 0x7F, 0x0D, 0x9C, 0xE9, 0x78, 0x0A, 0x9B,
    0xFC, 0x6D, 0x1F, 0x8E, 0xFB, 0x6A, 0x18, 0x89,
    0xF2, 0x63, 0x11, 0x80, 0xF5, 0x64, 0x16, 0x87,
    0xD8, 0x49, 0x3B, 0xAA, 0xDF, 0x4E, 0x3C, 0xAD,
    0xD6, 0x47, 0x35, 0xA4, 0xD1, 0x40, 0x32, 0xA3,
    0xC4, 0x55, 0x27, 0xB6, 0xC3, 0x52, 0x20, 0xB1,
    0xCA, 0x5B, 0x29, 0xB8, 0xCD, 0x5C, 0x2E, 0xBF,
    0x90, 0x01, 0x73, 0xE2, 0x97, 0x06, 0x74, 0xE5,
    0x9E, 0x0F, 0x7D, 0xEC, 0x99, 0x08, 0x7A, 0xEB,
    0x8C, 0x1D, 0x6F, 0xFE, 0x8B, 0x1A, 0x68, 0xF9,
    0x82, 0x13, 0x61, 0xF0, 0x85, 0x14, 0x66, 0xF7,
    0xA8, 0x39, 0x4B, 0xDA, 0xAF, 0x3E, 0x4C, 0xDD,
    0xA6, 0x37, 0x45, 0xD4, 0xA1, 0x30, 0x42, 0xD3,
    0xB4, 0x25, 0x57, 0xC6, 0xB3, 0x22, 0x50, 0xC1,
    0xBA, 0x2B, 0x59, 0xC8, 0xBD, 0x2C, 0x5E, 0xCF
  };

  assert(data);

  crc = 0;
  for (size_t i = 0; i < data_size; ++i) {
    crc = crc_lookup_table[crc ^ data[i]];
  }

  return crc;
}

void rmap_data_crc_put(unsigned char *const data, const size_t data_size);
