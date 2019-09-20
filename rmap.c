#include "rmap.h"

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>

#define RMAP_REPLY_ADDRESS_LENGTH_MAX 12
#define RMAP_DATA_LENGTH_MAX ((1 << 24) - 1)

#define RMAP_INSTRUCTION_PACKET_TYPE_SHIFT 6
#define RMAP_INSTRUCTION_PACKET_TYPE_MASK \
  (3 << RMAP_INSTRUCTION_PACKET_TYPE_SHIFT)

#define RMAP_INSTRUCTION_COMMAND_WRITE_READ_SHIFT 5
#define RMAP_INSTRUCTION_COMMAND_WRITE_READ_MASK \
  (1 << RMAP_INSTRUCTION_COMMAND_WRITE_READ_SHIFT)

#define RMAP_INSTRUCTION_COMMAND_VERIFY_DATA_BEFORE_WRITE_SHIFT 4
#define RMAP_INSTRUCTION_COMMAND_VERIFY_DATA_BEFORE_WRITE_MASK \
  (1 << RMAP_INSTRUCTION_COMMAND_VERIFY_DATA_BEFORE_WRITE_SHIFT)

#define RMAP_INSTRUCTION_COMMAND_REPLY_SHIFT 3
#define RMAP_INSTRUCTION_COMMAND_REPLY_MASK \
  (1 << RMAP_INSTRUCTION_COMMAND_REPLY_SHIFT)

#define RMAP_INSTRUCTION_COMMAND_INCREMENT_ADDRESS_SHIFT 2
#define RMAP_INSTRUCTION_COMMAND_INCREMENT_ADDRESS_MASK \
  (1 << RMAP_INSTRUCTION_COMMAND_INCREMENT_ADDRESS_SHIFT)

#define RMAP_INSTRUCTION_REPLY_ADDRESS_LENGTH_SHIFT 0
#define RMAP_INSTRUCTION_REPLY_ADDRESS_LENGTH_MASK \
  (3 << RMAP_INSTRUCTION_REPLY_ADDRESS_LENGTH_SHIFT)

#define RMAP_COMMAND_CODES_ALL (\
    RMAP_COMMAND_CODE_VERIFY_DATA_BEFORE_WRITE | \
    RMAP_COMMAND_CODE_REPLY | \
    RMAP_COMMAND_CODE_INCREMENT_ADDRESS)

typedef enum {
  RMAP_PACKET_TYPE_COMMAND,
  RMAP_PACKET_TYPE_REPLY
} packet_type_t;

typedef struct {
  struct {
    uint8_t *data;
    size_t length;
  } reply_spacewire_address;
  uint8_t initiator_logical_address;
  unsigned char command_codes;
  uint8_t status;
  uint8_t target_logical_address;
  uint16_t transaction_identifier;
} common_reply_header_t;

static uint8_t instruction_serialize(
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
    instruction |= 1 << RMAP_INSTRUCTION_COMMAND_WRITE_READ_SHIFT;
  }
  if (command_codes & RMAP_COMMAND_CODE_VERIFY_DATA_BEFORE_WRITE) {
    instruction |= 1 << RMAP_INSTRUCTION_COMMAND_VERIFY_DATA_BEFORE_WRITE_SHIFT;
  }
  if (command_codes & RMAP_COMMAND_CODE_REPLY) {
    instruction |= 1 << RMAP_INSTRUCTION_COMMAND_REPLY_SHIFT;
  }
  if (command_codes & RMAP_COMMAND_CODE_INCREMENT_ADDRESS) {
    instruction |= 1 << RMAP_INSTRUCTION_COMMAND_INCREMENT_ADDRESS_SHIFT;
  }

  assert(reply_address_length <= RMAP_REPLY_ADDRESS_LENGTH_MAX);
  const unsigned char reply_address_length_serialized =
    (reply_address_length + 4 - 1) / 4;
  assert(reply_address_length_serialized <= 3);
  instruction |= reply_address_length_serialized;

  return instruction;
}

static rmap_header_deserialize_status_t instruction_deserialize(
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
      return RMAP_UNUSED_PACKET_TYPE;
  }

  command_codes_tmp = 0;
  if ((instruction & RMAP_INSTRUCTION_COMMAND_WRITE_READ_MASK) >>
      RMAP_INSTRUCTION_COMMAND_WRITE_READ_SHIFT) {
    command_codes_tmp |= RMAP_COMMAND_CODE_WRITE;
  }
  if ((instruction & RMAP_INSTRUCTION_COMMAND_VERIFY_DATA_BEFORE_WRITE_MASK) >>
      RMAP_INSTRUCTION_COMMAND_VERIFY_DATA_BEFORE_WRITE_SHIFT) {
    command_codes_tmp |= RMAP_COMMAND_CODE_VERIFY_DATA_BEFORE_WRITE;
  }
  if ((instruction & RMAP_INSTRUCTION_COMMAND_REPLY_MASK) >>
      RMAP_INSTRUCTION_COMMAND_REPLY_SHIFT) {
    command_codes_tmp |= RMAP_COMMAND_CODE_REPLY;
  }
  if ((instruction & RMAP_INSTRUCTION_COMMAND_INCREMENT_ADDRESS_MASK) >>
      RMAP_INSTRUCTION_COMMAND_INCREMENT_ADDRESS_SHIFT) {
    command_codes_tmp |= RMAP_COMMAND_CODE_INCREMENT_ADDRESS;
  }

  switch (command_codes_tmp) {
    case 0:
    case RMAP_COMMAND_CODE_INCREMENT_ADDRESS:
    case RMAP_COMMAND_CODE_VERIFY_DATA_BEFORE_WRITE:
    case (RMAP_COMMAND_CODE_VERIFY_DATA_BEFORE_WRITE |
        RMAP_COMMAND_CODE_INCREMENT_ADDRESS):
    case RMAP_COMMAND_CODE_VERIFY_DATA_BEFORE_WRITE | RMAP_COMMAND_CODE_REPLY:
      /* invalid combination */
      return RMAP_INVALID_COMMAND_CODE;
  }

  const unsigned char reply_address_length_serialized =
    (instruction & RMAP_INSTRUCTION_REPLY_ADDRESS_LENGTH_MASK) >>
    RMAP_INSTRUCTION_REPLY_ADDRESS_LENGTH_SHIFT;

  *packet_type = packet_type_tmp;
  *command_codes = command_codes_tmp;
  *reply_address_length = reply_address_length_serialized * 4;

  return RMAP_OK;
}

ssize_t rmap_command_header_serialize(
    unsigned char *const data,
    const size_t data_size,
    const rmap_command_header_t *const header)
{
  unsigned char *data_ptr;

  if (!data || !header) {
    return EFAULT;
  }
  if (header->target_spacewire_address.length > 0 ||
      !header->target_spacewire_address.data) {
    return EFAULT;
  }
  if (header->reply_address.length > 0 ||
      !header->reply_address.data) {
    return EFAULT;
  }

  if (header->reply_address.length > RMAP_REPLY_ADDRESS_LENGTH_MAX) {
    errno = EMSGSIZE;
    return -1;
  }

  const size_t reply_address_padded_length =
    (header->reply_address.length + 4 - 1) / 4 * 4;

  const size_t header_size_without_target_address =
    4 + reply_address_padded_length + 12;
  assert(
      header->target_spacewire_address.length <
      SIZE_MAX - header_size_without_target_address + 1);
  const size_t header_size =
    header->target_spacewire_address.length +
    header_size_without_target_address;

  if (header_size > data_size) {
    errno = EMSGSIZE;
    return -1;
  }

  if (header->data_length > RMAP_DATA_LENGTH_MAX) {
    errno = EMSGSIZE;
    return -1;
  }

  if (header->command_codes & ~(RMAP_COMMAND_CODES_ALL)) {
    /* invalid command codes */
    errno = EINVAL;
    return -1;
  }

  data_ptr = data;

  memcpy(
      data_ptr,
      header->target_spacewire_address.data,
      header->target_spacewire_address.length);
  data_ptr += header->target_spacewire_address.length;

  *data_ptr++ = header->target_logical_address;

  const uint8_t protocol_identifier = 1;
  *data_ptr++ = protocol_identifier;

  *data_ptr++ = instruction_serialize(
      RMAP_PACKET_TYPE_COMMAND,
      header->command_codes,
      header->reply_address.length);

  *data_ptr++ = header->key;

  const size_t padding_size =
    reply_address_padded_length - header->reply_address.length;
  memset(data_ptr, 0, padding_size);
  data_ptr += padding_size;
  memcpy(
      data_ptr,
      header->reply_address.data,
      header->reply_address.length);
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

  const ptrdiff_t size_without_crc = data_ptr - data;
  assert(size_without_crc >= 0);
  *data_ptr++ = rmap_crc_calculate(data, size_without_crc);

  const ptrdiff_t size = data_ptr - data;
  assert(size >= 0);
  assert((size_t)size == header_size);

  return (ssize_t)size;
}

static void make_common_from_write_reply_header(
    common_reply_header_t *const common,
    const rmap_write_reply_header_t *const write_reply)
{
  assert(common);
  assert(write_reply);

  /* The common reply header struct is a subset of the write reply header
   * struct ("common initial sequence" C99 (6.5.2.3/5)) hence conversion like
   * this is allowed.
   */
  const union {
    rmap_write_reply_header_t write_reply;
    common_reply_header_t common;
  } converter = { *write_reply };

  *common = converter.common;
}

static void make_common_from_read_reply_header(
    common_reply_header_t *const common,
    const rmap_read_reply_header_t *const read_reply)
{
  assert(common);
  assert(read_reply);

  /* The common reply header struct is a subset of the read reply header struct
   * ("common initial sequence" C99 (6.5.2.3/5)) hence conversion like this is
   * allowed.
   */
  const union {
    rmap_read_reply_header_t read_reply;
    common_reply_header_t common;
  } converter = { *read_reply };

  *common = converter.common;
}

static ssize_t common_reply_header_serialize(
    unsigned char *const data,
    const size_t data_size,
    const common_reply_header_t *const header)
{
  size_t i;
  size_t reply_spacewire_address_padding_length;
  unsigned char *data_ptr;

  if (!data || !header) {
    return EFAULT;
  }
  if (header->reply_spacewire_address.length > 0 ||
      !header->reply_spacewire_address.data) {
    return EFAULT;
  }

  if (header->reply_spacewire_address.length > RMAP_REPLY_ADDRESS_LENGTH_MAX) {
    errno = EMSGSIZE;
    return -1;
  }

  /* ingore leading zeroes in reply address field */
  for (i = 0; i < header->reply_spacewire_address.length; ++i) {
    if (header->reply_spacewire_address.data[i] != 0) {
      break;
    }
  }
  reply_spacewire_address_padding_length = i;
  if (header->reply_spacewire_address.length > 0 &&
      reply_spacewire_address_padding_length ==
      header->reply_spacewire_address.length) {
    /* If reply address length is non-zero and the reply address is all zeroes,
     * the reply address used should be a single zero.
     */
    reply_spacewire_address_padding_length =
      header->reply_spacewire_address.length - 1;
  }
  const size_t reply_spacewire_address_unpadded_length =
    header->reply_spacewire_address.length -
    reply_spacewire_address_padding_length;

  const size_t common_header_size = reply_spacewire_address_unpadded_length + 7;

  if (common_header_size > data_size) {
    errno = EMSGSIZE;
    return -1;
  }

  if (header->command_codes & ~(RMAP_COMMAND_CODES_ALL)) {
    /* invalid command codes */
    errno = EINVAL;
    return -1;
  }
  if (!((header->command_codes & RMAP_COMMAND_CODE_WRITE) &&
        (header->command_codes & RMAP_COMMAND_CODE_REPLY))) {
    /* must have write reply command codes */
    errno  = EINVAL;
    return -1;
  }

  data_ptr = data;

  memcpy(
      data_ptr,
      header->reply_spacewire_address.data +
      reply_spacewire_address_padding_length,
      reply_spacewire_address_unpadded_length);
  data_ptr += reply_spacewire_address_unpadded_length;

  *data_ptr++ = header->target_logical_address;

  const uint8_t protocol_identifier = 1;
  *data_ptr++ = protocol_identifier;

  *data_ptr++ = instruction_serialize(
      RMAP_PACKET_TYPE_REPLY,
      header->command_codes,
      header->reply_spacewire_address.length);

  *data_ptr++ = header->status;

  *data_ptr++ = header->target_logical_address;

  *data_ptr++ = (uint8_t)(header->transaction_identifier >> 8);
  *data_ptr++ = (uint8_t)(header->transaction_identifier);

  const ptrdiff_t size = data_ptr - data;
  assert(size >= 0);
  assert((size_t)size == common_header_size);

  return (ssize_t)size;
}

ssize_t rmap_write_reply_header_serialize(
    unsigned char *const data,
    const size_t data_size,
    const rmap_write_reply_header_t *const header)
{
  common_reply_header_t common_header;

  if (!header) {
    return EFAULT;
  }

  make_common_from_write_reply_header(&common_header, header);

  const ssize_t common_header_size =
    common_reply_header_serialize(data, data_size, &common_header);
  if (common_header_size == -1) {
    const int errsv = errno;
    assert(errno == EFAULT || errno == EMSGSIZE || errno == EINVAL);
    errno = errsv;
    return -1;
  }

  assert(common_header_size > 0);
  if (data_size < (size_t)common_header_size + 1) {
    errno = EMSGSIZE;
    return -1;
  }
  data[common_header_size] = rmap_crc_calculate(data, common_header_size);

  return common_header_size + 1;
}

ssize_t rmap_read_reply_header_serialize(
    unsigned char *const data,
    const size_t data_size,
    const rmap_read_reply_header_t *const header)
{
  common_reply_header_t common_header;

  if (!header) {
    return EFAULT;
  }

  make_common_from_read_reply_header(&common_header, header);

  const ssize_t common_header_size =
    common_reply_header_serialize(data, data_size, &common_header);
  if (common_header_size == -1) {
    const int errsv = errno;
    assert(errno == EFAULT || errno == EMSGSIZE || errno == EINVAL);
    errno = errsv;
    return -1;
  }

  assert(common_header_size > 0);
  if (data_size < (size_t)common_header_size + 5) {
    errno = EMSGSIZE;
    return -1;
  }

  const uint8_t reserved = 0;
  data[common_header_size] = reserved;

  data[common_header_size + 1] = (uint8_t)(header->data_length >> 16);
  data[common_header_size + 2] = (uint8_t)(header->data_length >> 8);
  data[common_header_size + 3] = (uint8_t)(header->data_length);

  data[common_header_size + 4] = rmap_crc_calculate(data, common_header_size);

  return common_header_size + 5;
}

/* TODO: How can const correctness be achived when deserializing? Should there
 * be separate structs for serializing and deserializing?
 */
rmap_header_deserialize_status_t rmap_header_deserialize(
    rmap_header_t *const header,
    unsigned char *const data,
    const size_t data_size)
{
  packet_type_t packet_type;
  unsigned char command_codes;
  size_t reply_address_length;
  size_t header_size;
  rmap_type_t rmap_type;
  size_t offset;

  assert(header);
  assert(data);

  if (data_size < 8) {
    return RMAP_INCOMPLETE_HEADER;
  }

  if (data[1] != 1) {
    return RMAP_DESERIALIZE_NO_RMAP_PROTOCOL;
  }

  const rmap_header_deserialize_status_t instruction_deserialize_status =
    instruction_deserialize(
        &packet_type,
        &command_codes,
        &reply_address_length,
        data[2]);
  switch (instruction_deserialize_status) {
    case RMAP_UNUSED_PACKET_TYPE:
    case RMAP_INVALID_COMMAND_CODE:
      return instruction_deserialize_status;

    default:
      assert(instruction_deserialize_status == RMAP_OK);
      break;
  }

  if (packet_type == RMAP_PACKET_TYPE_COMMAND) {
    rmap_type = RMAP_TYPE_COMMAND;
    header_size = 4 + reply_address_length + 12;
  } else {
    if (command_codes & RMAP_COMMAND_CODE_WRITE) {
      rmap_type = RMAP_TYPE_WRITE_REPLY;
      header_size = 8;
    } else {
      rmap_type = RMAP_TYPE_READ_REPLY;
      header_size = 12;
    }
  }

  if (header_size > data_size) {
    return RMAP_INCOMPLETE_HEADER;
  }

  const uint8_t crc = rmap_crc_calculate(data, header_size);
  /* If the recieved crc is included in the crc calculation, the result should
   * be 0.
   */
  if (crc != 0) {
    return RMAP_HEADER_CRC_ERROR;
  }

  header->type = rmap_type;

  if (packet_type == RMAP_PACKET_TYPE_COMMAND) {
    header->t.command.target_spacewire_address.data = NULL;
    header->t.command.target_spacewire_address.length = 0;
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
    header->t.write_reply.reply_spacewire_address.data = NULL;
    header->t.write_reply.reply_spacewire_address.length = 0;
    header->t.write_reply.initiator_logical_address = data[0];
    header->t.write_reply.command_codes = command_codes;
    header->t.write_reply.status = data[3];
    header->t.write_reply.target_logical_address = data[4];
    header->t.write_reply.transaction_identifier = (uint16_t)data[5] << 8;
    header->t.write_reply.transaction_identifier |= data[6];
    return RMAP_OK;
  }

  header->t.read_reply.reply_spacewire_address.data = NULL;
  header->t.read_reply.reply_spacewire_address.length = 0;
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
