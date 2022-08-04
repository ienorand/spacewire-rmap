#include "rmap.h"

#include <assert.h>
#include <string.h>
#include <stdbool.h>

#define RMAP_DATA_LENGTH_MAX ((1 << 24) - 1)

#define RMAP_INSTRUCTION_PACKET_TYPE_SHIFT 6
#define RMAP_INSTRUCTION_PACKET_TYPE_MASK \
  (3 << RMAP_INSTRUCTION_PACKET_TYPE_SHIFT)

#define RMAP_INSTRUCTION_COMMAND_CODE_SHIFT 2
#define RMAP_INSTRUCTION_COMMAND_CODE_MASK \
  (0xF << RMAP_INSTRUCTION_COMMAND_CODE_SHIFT)

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

uint8_t rmap_get_protocol(const uint8_t *const header)
{
  return header[1];
}

void rmap_set_protocol(uint8_t *const header)
{
  header[1] = 1;
}

uint8_t rmap_get_instruction(const uint8_t *const header)
{
  return header[2];
}

void rmap_set_instruction(uint8_t *const header, const uint8_t instruction)
{
  header[2] = instruction;
}

bool rmap_is_instruction_command(const uint8_t instruction)
{
  return ((instruction & RMAP_INSTRUCTION_PACKET_TYPE_MASK) >>
    RMAP_INSTRUCTION_PACKET_TYPE_SHIFT) & 0x1;
}

bool rmap_is_command(const uint8_t *const header)
{
  return rmap_is_instruction_command(rmap_get_instruction(header));
}

bool rmap_is_instruction_unused_packet_type(const uint8_t instruction)
{
  return ((instruction & RMAP_INSTRUCTION_PACKET_TYPE_MASK) >>
    RMAP_INSTRUCTION_PACKET_TYPE_SHIFT) & 0x2;
}

bool rmap_is_unused_packet_type(const uint8_t *const header)
{
  return rmap_is_instruction_unused_packet_type(rmap_get_instruction(header));
}

bool rmap_is_instruction_write(const uint8_t instruction)
{
  return instruction & RMAP_INSTRUCTION_COMMAND_WRITE_MASK;
}

bool rmap_is_write(const uint8_t *const header)
{
  return rmap_is_instruction_write(rmap_get_instruction(header));
}

bool rmap_is_instruction_verify_data_before_write(const uint8_t instruction)
{
  return instruction & RMAP_INSTRUCTION_COMMAND_VERIFY_MASK;
}

bool rmap_is_verify_data_before_write(const uint8_t *const header)
{
  return
    rmap_is_instruction_verify_data_before_write(rmap_get_instruction(header));
}

bool rmap_is_instruction_with_reply(const uint8_t instruction)
{
  return instruction & RMAP_INSTRUCTION_COMMAND_REPLY_MASK;
}

bool rmap_is_with_reply(const uint8_t *const header)
{
  return rmap_is_instruction_with_reply(rmap_get_instruction(header));
}

bool rmap_is_instruction_increment_address(const uint8_t instruction)
{
  return instruction & RMAP_INSTRUCTION_COMMAND_INCREMENT_MASK;
}

bool rmap_is_increment_address(const uint8_t *const header)
{
  return rmap_is_instruction_increment_address(rmap_get_instruction(header));
}

bool rmap_is_instruction_unused_command_code(const uint8_t instruction)
{
  const int raw_unshifted = instruction & RMAP_INSTRUCTION_COMMAND_CODE_MASK;

  switch (raw_unshifted) {
    case 0x0:
    case RMAP_INSTRUCTION_COMMAND_INCREMENT_MASK:
    case RMAP_INSTRUCTION_COMMAND_VERIFY_MASK:
    case (RMAP_INSTRUCTION_COMMAND_VERIFY_MASK |
        RMAP_INSTRUCTION_COMMAND_INCREMENT_MASK):
    case (RMAP_INSTRUCTION_COMMAND_VERIFY_MASK |
        RMAP_INSTRUCTION_COMMAND_REPLY_MASK):
      return true;

    default:
      break;
  }

  return false;
}

bool rmap_is_unused_command_code(const uint8_t *const header)
{
  return rmap_is_instruction_unused_command_code(rmap_get_instruction(header));
}

uint8_t rmap_get_key(const uint8_t *const command_header)
{
  return command_header[3];
}

void rmap_set_key(uint8_t *const header, const uint8_t key)
{
  header[3] = key;
}

uint8_t rmap_get_status(const uint8_t *const header)
{
  return header[3];
}

void rmap_set_status(uint8_t *const header, const uint8_t status)
{
  header[3] = status;
}

/** Calculate the padded reply address size from an instruction field.
 *
 * @param instruction Instruction field.
 *
 * @return Padded reply address size.
 */
static size_t calculate_reply_address_padded_size(const uint8_t instruction)
{
  const unsigned int raw =
    (instruction & RMAP_INSTRUCTION_REPLY_ADDRESS_LENGTH_MASK) >>
    RMAP_INSTRUCTION_REPLY_ADDRESS_LENGTH_SHIFT;

  return raw * 4;
}

rmap_status_t rmap_get_reply_address(
    uint8_t *reply_address,
    size_t *const reply_address_size,
    const size_t reply_address_max_size,
    const uint8_t *const header)
{
  const uint8_t *reply_address_padded;

  assert(reply_address);
  assert(reply_address_size);
  assert(header);

  const size_t reply_address_padded_size =
    calculate_reply_address_padded_size(rmap_get_instruction(header));
  reply_address_padded = header + 4;

  uint8_t *const reply_address0 = reply_address;

  *reply_address_size = 0;
  for (size_t i = 0; i < reply_address_padded_size; ++i) {
    /* Ignore leading zeroes. */
    if (*reply_address_size == 0 && reply_address_padded[i] == 0x00) {
      continue;
    }

    if (*reply_address_size + 1 > reply_address_max_size) {
      return RMAP_NOT_ENOUGH_SPACE;
    }
    *reply_address++ = reply_address_padded[i];
    ++(*reply_address_size);
  }

  if (reply_address_padded_size > 0 && *reply_address_size == 0) {
    /* If reply address length is non-zero and the reply address is all zeroes,
     * the reply address used should be a single zero.
     */
    if (reply_address_max_size == 0) {
      return RMAP_NOT_ENOUGH_SPACE;
    }
    reply_address0[0] = 0x00;
    *reply_address_size = 1;
  }

  return RMAP_OK;
}

void rmap_set_reply_address(
    uint8_t *const header,
    const uint8_t *const reply_address,
    const size_t reply_address_size)
{
  uint8_t *reply_address_padded;

  reply_address_padded = header + 4;

  const size_t padding_size =
    calculate_reply_address_padded_size(rmap_get_instruction(header)) -
    reply_address_size;
  memset(reply_address_padded, 0x00, padding_size);

  memcpy(
      reply_address_padded + padding_size,
      reply_address,
      reply_address_size);
}

uint8_t rmap_get_target_logical_address(const uint8_t *const header)
{
  if (rmap_is_command(header)) {
    return header[0];
  }

  /* Reply. */
  return header[4];
}

void rmap_set_target_logical_address(
    uint8_t *const header,
    const uint8_t target_logical_address)
{
  if (rmap_is_command(header)) {
    header[0] = target_logical_address;
    return;
  }

  /* Reply. */
  header[4] = target_logical_address;
}

uint8_t rmap_get_initiator_logical_address(const uint8_t *const header)
{
  if (rmap_is_command(header)) {
    size_t reply_address_padded_size =
      calculate_reply_address_padded_size(rmap_get_instruction(header));
    return header[4 + reply_address_padded_size];
  }

  /* Reply. */
  return header[0];
}

void rmap_set_initiator_logical_address(
    uint8_t *const header,
    const uint8_t initiator_logical_address)
{
  if (rmap_is_command(header)) {
    size_t reply_address_padded_size =
      calculate_reply_address_padded_size(rmap_get_instruction(header));
    header[4 + reply_address_padded_size] = initiator_logical_address;
    return;
  }

  /* Reply. */
  header[0] = initiator_logical_address;
}

uint16_t rmap_get_transaction_identifier(const uint8_t *const header)
{
  size_t offset;

  offset = 4 + 1;
  if (rmap_is_command(header)) {
    size_t reply_address_padded_size =
      calculate_reply_address_padded_size(rmap_get_instruction(header));
    offset += reply_address_padded_size;
  }

  return (header[offset] << 8) | (header[offset + 1] << 0);
}

void rmap_set_transaction_identifier(
    uint8_t *const header,
    const uint16_t transaction_identifier)
{
  size_t offset;

  offset = 4 + 1;
  if (rmap_is_command(header)) {
    size_t reply_address_padded_size =
      calculate_reply_address_padded_size(rmap_get_instruction(header));
    offset += reply_address_padded_size;
  }

  header[offset] = transaction_identifier >> 8;
  header[offset + 1] = transaction_identifier & 0xFF;
}

void rmap_set_reserved(uint8_t *const header)
{
  header[7] = 0;
}

uint8_t rmap_get_extended_address(const uint8_t *const header)
{
  size_t reply_address_padded_size =
    calculate_reply_address_padded_size(rmap_get_instruction(header));
  return header[4 + reply_address_padded_size + 3];
}

void rmap_set_extended_address(
    uint8_t *const header,
    const uint8_t extended_address)
{
  size_t reply_address_padded_size =
    calculate_reply_address_padded_size(rmap_get_instruction(header));
  header[4 + reply_address_padded_size + 3] = extended_address;
}

uint32_t rmap_get_address(const uint8_t *const header)
{
  size_t reply_address_padded_size =
    calculate_reply_address_padded_size(rmap_get_instruction(header));
  const size_t offset = 4 + reply_address_padded_size + 4;
  return ((uint32_t)header[offset + 0] << 24) |
    (header[offset + 1] << 16) |
    (header[offset + 2] << 8) |
    (header[offset + 3] << 0);
}

void rmap_set_address(uint8_t *const header, const uint32_t address)
{
  size_t reply_address_padded_size =
    calculate_reply_address_padded_size(rmap_get_instruction(header));
  const size_t offset = 4 + reply_address_padded_size + 4;

  header[offset + 0] = (address >> 24) & 0xFF;
  header[offset + 1] = (address >> 16) & 0xFF;
  header[offset + 2] = (address >> 8) & 0xFF;
  header[offset + 3] = (address >> 0) & 0xFF;
}

/** Calculate the RMAP header size from an instruction field.
 *
 * @pre @p header must contain at least RMAP_HEADER_MINIMUM_SIZE bytes.
 * @pre @p header must have a correct packet type field.
 * @pre @p header must have a correct command field.
 *
 * @param instruction Instruction field.
 *
 * @return RMAP header size.
 */
static size_t calculate_header_size(const uint8_t instruction)
{
  if (rmap_is_instruction_command(instruction)) {
      return RMAP_COMMAND_HEADER_STATIC_SIZE +
        calculate_reply_address_padded_size(instruction);
  }

  if (rmap_is_instruction_write(instruction)) {
    return RMAP_WRITE_REPLY_HEADER_STATIC_SIZE;
  }

  return RMAP_READ_REPLY_HEADER_STATIC_SIZE;
}

uint32_t rmap_get_header_data_length(const uint8_t *const header)
{
  size_t offset;

  const uint8_t instruction = rmap_get_instruction(header);

  offset = RMAP_READ_REPLY_HEADER_STATIC_SIZE - 4;
  if (rmap_is_instruction_command(instruction)) {
    offset = RMAP_COMMAND_HEADER_STATIC_SIZE +
      calculate_reply_address_padded_size(instruction) - 4;
  } else if (rmap_is_instruction_write(instruction)) {
    /* Write reply has no data. */
    return 0;
  }

  return (header[offset + 0] << 16) |
    (header[offset + 1] << 8) |
    (header[offset + 2] << 0);
}

void rmap_set_data_length(uint8_t *const header, const uint32_t data_length)
{
  size_t offset;

  const uint8_t instruction = rmap_get_instruction(header);

  offset = RMAP_READ_REPLY_HEADER_STATIC_SIZE - 4;
  if (rmap_is_instruction_command(instruction)) {
    offset = RMAP_COMMAND_HEADER_STATIC_SIZE +
      calculate_reply_address_padded_size(instruction) - 4;
  }

  header[offset + 0] = (data_length >> 16) & 0xFF;
  header[offset + 1] = (data_length >> 8) & 0xFF;
  header[offset + 2] = (data_length >> 0) & 0xFF;
}

void rmap_calculate_and_set_header_crc(uint8_t *const header)
{
  const size_t header_size =
    calculate_header_size(rmap_get_instruction(header));
  header[header_size - 1] = rmap_crc_calculate(header, header_size - 1);
}

size_t rmap_calculate_header_size(const uint8_t *const header)
{
  return calculate_header_size(rmap_get_instruction(header));
}

rmap_status_t rmap_verify_header_integrity(
    const uint8_t *const header,
    const size_t size)
{
  size_t header_size;

  assert(header);

  if (size < RMAP_HEADER_MINIMUM_SIZE) {
    return RMAP_INCOMPLETE_HEADER;
  }

  if (rmap_get_protocol(header) != 1) {
    return RMAP_NO_RMAP_PROTOCOL;
  }

  header_size = calculate_header_size(rmap_get_instruction(header));

  if (size < header_size) {
    return RMAP_INCOMPLETE_HEADER;
  }

  const uint8_t crc = rmap_crc_calculate(header, header_size);
  /* If the received crc is included in the crc calculation, the result should
   * be 0.
   */
  if (crc != 0) {
    return RMAP_HEADER_CRC_ERROR;
  }

  return RMAP_OK;
}

rmap_status_t rmap_verify_header_instruction(const uint8_t *const header)
{
  const uint8_t instruction = rmap_get_instruction(header);

  if (!rmap_is_instruction_command(instruction)) {
    /* TODO: Based on RMAP standard, unused packet type is also "invalid
     * reply".
     */
    if (rmap_is_instruction_unused_packet_type(instruction)) {
      /* Reply packet type with packet type reserved bit set */
      return RMAP_UNUSED_PACKET_TYPE;
    }

    if (!rmap_is_instruction_with_reply(instruction)) {
      /* Reply packet type without command code reply bit set. */
      return RMAP_INVALID_REPLY;
    }
  }

  if (rmap_is_instruction_unused_packet_type(instruction)) {
    return RMAP_UNUSED_PACKET_TYPE;
  }

  if (rmap_is_instruction_unused_command_code(instruction)) {
    return RMAP_UNUSED_COMMAND_CODE;
  }

  return RMAP_OK;
}

/** Verify a potential RMAP header.
 *
 * @p size May be larger than the size of the header being verified.
 *
 * @param[in] header Potential RMAP header.
 * @param size Number of bytes in @p header.
 *
 * @retval RMAP_INCOMPLETE_HEADER @p size is too small to fit the whole header.
 * @retval RMAP_NO_RMAP_PROTOCOL The protocol field indicates that this is not
 *         an RMAP packet.
 * @retval RMAP_HEADER_CRC_ERROR The header CRC indicates that errors are
 *         present in the header.
 * @retval RMAP_UNUSED_PACKET_TYPE The packet type field has the reserved bit
 *         set.
 * @retval RMAP_UNUSED_COMMAND_CODE The command field contains a reserved
 *         command code or the packet type is a reply without the with-reply
 *         bit set.
 * @retval RMAP_INVALID_REPLY The packet type field indicates that this is a
 *         reply but the command code field do not have the reply bit set.
 * @retval RMAP_OK Header is valid.
 */
static rmap_status_t verify_header(
    const uint8_t *const header,
    const size_t size)
{
  rmap_status_t status;

  assert(header);

  status = rmap_verify_header_integrity(header, size);
  if (status != RMAP_OK)
  {
    return status;
  }

  return rmap_verify_header_instruction(header);
}

/** Verify the data field in a packet with a verified RMAP write command or
 *  read reply header.
 *
 * @pre @p packet must contain a verified RMAP command or read reply header.
 * @pre @p size Must be equal to the size of the packet being verified.
 *
 * @param[in] packet Packet with a verified RMAP command or read reply header.
 * @param size Number of bytes in @p packet.
 *
 * @retval RMAP_EARLY_EOP @p size is too small to fit the whole packet.
 * @retval RMAP_ECSS_TOO_MUCH_DATA @p size is larger than the packet based on
 *         the data length field.
 * @retval RMAP_ECSS_INVALID_DATA_CRC The data CRC indicates that errors are
 *         present in the data field.
 * @retval RMAP_OK Data field is valid.
 */
static rmap_status_t verify_data(
    const uint8_t *const packet,
    const size_t size)
{
  assert(packet);

  const size_t data_offset =
    calculate_header_size(rmap_get_instruction(packet));
  const size_t data_length = rmap_get_header_data_length(packet);

  if (size < data_offset + data_length + 1) {
    return RMAP_EARLY_EOP;
  }

  if (size > data_offset + data_length + 1) {
    return RMAP_ECSS_TOO_MUCH_DATA;
  }

  const uint8_t data_crc =
    rmap_crc_calculate(packet + data_offset, data_length + 1);
  /* If the crc is included in the crc calculation, the result should be 0. */
  if (data_crc != 0) {
    return RMAP_ECSS_INVALID_DATA_CRC;
  }

  return RMAP_OK;
}

/** Make an RMAP instruction field.
 *
 * Creating invalid instruction fields with unused packet types or unused
 * command codes is supported in order to allow ceating invalid RMAP headers
 * for testing purposes.
 *
 * @p packet_type uses a different representation of packet types compared to
 * the RMAP representation in the instruction field.
 *
 * @p command_code uses a different representation of command code flags
 * compared to the RMAP representation in the instruction field.
 *
 * @param[out] instruction Destination for instruction field.
 * @param packet_type Representation of packet type to set in instruction
 *        field.
 * @param command_code Representation of command code flags to set in
 *        instruction field.
 * @param reply_address_unpadded_size Reply address size without leading
 *        zero-padding used to calculate and set the reply address length
 *        field.
 *
 * @retval RMAP_INVALID_PACKET_TYPE @p packet_type contains an unrepresentable
 *         packet type.
 * @retval RMAP_INVALID_COMMAND_CODE @p command_code contains an
 *         unrepresentable command code.
 * @retval RMAP_REPLY_ADDRESS_TOO_LONG @p reply_address_unpadded_size is larger
 *         than RMAP_REPLY_ADDRESS_LENGTH_MAX.
 * @retval RMAP_OK Instruction created successfully.
 */
static rmap_status_t make_instruction(
    uint8_t *const instruction,
    const rmap_packet_type_t packet_type,
    const int command_code,
    const size_t reply_address_unpadded_size)
{
  assert(instruction);

  *instruction = 0;

  switch (packet_type) {
    case RMAP_PACKET_TYPE_COMMAND:
      *instruction |= 0x1 << RMAP_INSTRUCTION_PACKET_TYPE_SHIFT;
      break;

    case RMAP_PACKET_TYPE_REPLY:
      *instruction |= 0x0 << RMAP_INSTRUCTION_PACKET_TYPE_SHIFT;
      break;

    case RMAP_PACKET_TYPE_COMMAND_RESERVED:
      *instruction |= 0x3 << RMAP_INSTRUCTION_PACKET_TYPE_SHIFT;
      break;

    case RMAP_PACKET_TYPE_REPLY_RESERVED:
      *instruction |= 0x2 << RMAP_INSTRUCTION_PACKET_TYPE_SHIFT;
      break;

    default:
      return RMAP_INVALID_PACKET_TYPE;
  }

  if (command_code < 0 || command_code > RMAP_COMMAND_CODES_ALL) {
    return RMAP_INVALID_COMMAND_CODE;
  }

  if (command_code & RMAP_COMMAND_CODE_WRITE) {
    *instruction |= 1 << RMAP_INSTRUCTION_COMMAND_WRITE_SHIFT;
  }
  if (command_code & RMAP_COMMAND_CODE_VERIFY) {
    *instruction |= 1 << RMAP_INSTRUCTION_COMMAND_VERIFY_SHIFT;
  }
  if (command_code & RMAP_COMMAND_CODE_REPLY) {
    *instruction |= 1 << RMAP_INSTRUCTION_COMMAND_REPLY_SHIFT;
  }
  if (command_code & RMAP_COMMAND_CODE_INCREMENT) {
    *instruction |= 1 << RMAP_INSTRUCTION_COMMAND_INCREMENT_SHIFT;
  }

  if (reply_address_unpadded_size > RMAP_REPLY_ADDRESS_LENGTH_MAX) {
    return RMAP_REPLY_ADDRESS_TOO_LONG;
  }
  /* Unpadded size divided by 4, rounded up. */
  const unsigned char reply_address_length_representation =
    (reply_address_unpadded_size + (4 - 1)) / 4;
  *instruction |= reply_address_length_representation <<
    RMAP_INSTRUCTION_REPLY_ADDRESS_LENGTH_SHIFT;

  return RMAP_OK;
}

rmap_status_t rmap_initialize_header(
    uint8_t *const header,
    const size_t max_size,
    const rmap_packet_type_t packet_type,
    const int command_code,
    const size_t reply_address_unpadded_size)
{
  uint8_t instruction;

  assert(header);

  const rmap_status_t status = make_instruction(
      &instruction,
      packet_type,
      command_code,
      reply_address_unpadded_size);
  switch (status) {
    case RMAP_INVALID_PACKET_TYPE:
    case RMAP_INVALID_COMMAND_CODE:
    case RMAP_REPLY_ADDRESS_TOO_LONG:
      return status;

    default:
      assert(status == RMAP_OK);
      break;
  }

  if (calculate_header_size(instruction) > max_size) {
    return RMAP_NOT_ENOUGH_SPACE;
  }

  rmap_set_protocol(header);
  rmap_set_instruction(header, instruction);

  return RMAP_OK;
}

static rmap_status_t serialize_command_header(
    size_t *const serialized_size,
    unsigned char *const data,
    const size_t data_size,
    const rmap_send_command_header_t *const header)
{
  rmap_status_t status;
  size_t target_address_padding_size;

  assert(serialized_size);
  assert(data);
  assert(header);

  assert(header->target_address.length == 0 || header->target_address.data);

  if (header->data_length > RMAP_DATA_LENGTH_MAX) {
    return RMAP_DATA_LENGTH_TOO_BIG;
  }

  if (header->target_address.length + RMAP_HEADER_MINIMUM_SIZE > data_size) {
    return RMAP_NOT_ENOUGH_SPACE;
  }
  target_address_padding_size = 0;
  for (size_t i = 0; i < header->target_address.length; ++i) {
    if (header->target_address.data[i] != 0x00) {
      break;
    }

    ++target_address_padding_size;
  }
  memcpy(
      data,
      header->target_address.data + target_address_padding_size,
      header->target_address.length - target_address_padding_size);

  uint8_t *const packet =
    data + header->target_address.length - target_address_padding_size;
  const size_t packet_max_size =
    data_size - (header->target_address.length - target_address_padding_size);

  status = rmap_initialize_header(
      packet,
      packet_max_size,
      RMAP_PACKET_TYPE_COMMAND,
      header->command_codes,
      header->reply_address.length);
  if (status != RMAP_OK) {
    return status;
  }

  /* No support for serializing invalid headers. */
  status = rmap_verify_header_instruction(packet);
  if (status != RMAP_OK) {
    return status;
  }

  rmap_set_target_logical_address(packet, header->target_logical_address);
  rmap_set_key(packet, header->key);
  rmap_set_reply_address(
      packet,
      header->reply_address.data,
      header->reply_address.length);
  rmap_set_initiator_logical_address(
      packet,
      header->initiator_logical_address);
  rmap_set_transaction_identifier(packet, header->transaction_identifier);
  rmap_set_extended_address(packet, header->extended_address);
  rmap_set_address(packet, header->address);
  rmap_set_data_length(packet, header->data_length);
  rmap_calculate_and_set_header_crc(packet);

  *serialized_size = calculate_header_size(rmap_get_instruction(packet));

  return RMAP_OK;
}

static rmap_status_t serialize_write_reply_header(
    size_t *const serialized_size,
    unsigned char *const data,
    const size_t data_size,
    const rmap_send_write_reply_header_t *const header)
{
  rmap_status_t status;
  size_t reply_address_padding_size;

  assert(serialized_size);
  assert(data);
  assert(header);

  if (header->reply_address.length + RMAP_HEADER_MINIMUM_SIZE > data_size) {
    return RMAP_NOT_ENOUGH_SPACE;
  }
  reply_address_padding_size = 0;
  for (size_t i = 0; i < header->reply_address.length; ++i) {
    if (header->reply_address.data[i] != 0x00) {
      break;
    }

    ++reply_address_padding_size;
  }
  memcpy(
      data,
      header->reply_address.data + reply_address_padding_size,
      header->reply_address.length - reply_address_padding_size);

  uint8_t *const packet =
    data + header->reply_address.length - reply_address_padding_size;
  const size_t packet_max_size =
    data_size - (header->reply_address.length - reply_address_padding_size);

  status = rmap_initialize_header(
      packet,
      packet_max_size,
      RMAP_PACKET_TYPE_REPLY,
      header->command_codes,
      header->reply_address.length);
  if (status != RMAP_OK) {
    return status;
  }

  /* No support for serializing invalid headers. */
  status = rmap_verify_header_instruction(packet);
  if (status != RMAP_OK) {
    if (status == RMAP_INVALID_REPLY) {
      status = RMAP_NO_REPLY;
    }
    return status;
  }

  if (!(header->command_codes & RMAP_COMMAND_CODE_WRITE)) {
    return RMAP_UNUSED_COMMAND_CODE;
  }

  rmap_set_initiator_logical_address(
      packet,
      header->initiator_logical_address);
  rmap_set_status(packet, header->status);
  rmap_set_target_logical_address(packet, header->target_logical_address);
  rmap_set_transaction_identifier(packet, header->transaction_identifier);
  rmap_calculate_and_set_header_crc(packet);

  *serialized_size = calculate_header_size(rmap_get_instruction(packet));

  return RMAP_OK;
}

static rmap_status_t serialize_read_reply_header(
    size_t *const serialized_size,
    unsigned char *const data,
    const size_t data_size,
    const rmap_send_read_reply_header_t *const header)
{
  rmap_status_t status;
  size_t reply_address_padding_size;

  assert(serialized_size);
  assert(data);
  assert(header);

  if (header->data_length > RMAP_DATA_LENGTH_MAX) {
    return RMAP_DATA_LENGTH_TOO_BIG;
  }

  if (header->reply_address.length + RMAP_HEADER_MINIMUM_SIZE > data_size) {
    return RMAP_NOT_ENOUGH_SPACE;
  }
  reply_address_padding_size = 0;
  for (size_t i = 0; i < header->reply_address.length; ++i) {
    if (header->reply_address.data[i] != 0x00) {
      break;
    }

    ++reply_address_padding_size;
  }
  memcpy(
      data,
      header->reply_address.data + reply_address_padding_size,
      header->reply_address.length - reply_address_padding_size);

  uint8_t *const packet =
    data + header->reply_address.length - reply_address_padding_size;
  const size_t packet_max_size =
    data_size - (header->reply_address.length - reply_address_padding_size);

  status = rmap_initialize_header(
      packet,
      packet_max_size,
      RMAP_PACKET_TYPE_REPLY,
      header->command_codes,
      header->reply_address.length);
  if (status != RMAP_OK) {
    return status;
  }

  /* No support for serializing invalid headers. */
  status = rmap_verify_header_instruction(packet);
  if (status != RMAP_OK) {
    if (status == RMAP_INVALID_REPLY) {
      status = RMAP_NO_REPLY;
    }
    return status;
  }

  if (header->command_codes & RMAP_COMMAND_CODE_WRITE) {
    return RMAP_UNUSED_COMMAND_CODE;
  }

  rmap_set_initiator_logical_address(
      packet,
      header->initiator_logical_address);
  rmap_set_status(packet, header->status);
  rmap_set_target_logical_address(packet, header->target_logical_address);
  rmap_set_transaction_identifier(packet, header->transaction_identifier);
  rmap_set_reserved(packet);
  rmap_set_data_length(packet, header->data_length);
  rmap_calculate_and_set_header_crc(packet);

  *serialized_size = calculate_header_size(rmap_get_instruction(packet));

  return RMAP_OK;
}

rmap_status_t rmap_header_initialize_reply(
    rmap_send_header_t *const reply,
    const rmap_receive_command_header_t *const command)
{
  assert(reply);
  assert(command);

  if (!(command->command_codes & RMAP_COMMAND_CODE_REPLY)) {
    return RMAP_NO_REPLY;
  }

  if (command->command_codes & RMAP_COMMAND_CODE_WRITE) {
    reply->type = RMAP_TYPE_WRITE_REPLY;
    reply->t.write_reply.reply_address.length = command->reply_address.length;
    memcpy(
        reply->t.write_reply.reply_address.data,
        command->reply_address.data,
        command->reply_address.length);
    reply->t.write_reply.initiator_logical_address =
      command->initiator_logical_address;
    reply->t.write_reply.command_codes = command->command_codes;
    reply->t.write_reply.status = 0;
    reply->t.write_reply.target_logical_address =
      command->target_logical_address;
    reply->t.write_reply.transaction_identifier =
      command->transaction_identifier;
  } else {
    reply->type = RMAP_TYPE_READ_REPLY;
    reply->t.read_reply.reply_address.length = command->reply_address.length;
    memcpy(
        reply->t.read_reply.reply_address.data,
        command->reply_address.data,
        command->reply_address.length);
    reply->t.read_reply.initiator_logical_address =
      command->initiator_logical_address;
    reply->t.read_reply.command_codes = command->command_codes;
    reply->t.read_reply.status = 0;
    reply->t.read_reply.target_logical_address =
      command->target_logical_address;
    reply->t.read_reply.transaction_identifier =
      command->transaction_identifier;
    reply->t.read_reply.data_length = command->data_length;
  }

  return RMAP_OK;
}

rmap_status_t rmap_header_calculate_serialized_size(
    size_t *const serialized_size,
    const rmap_send_header_t *const header)
{
  rmap_status_t status;
  uint8_t instruction;
  rmap_packet_type_t packet_type;
  unsigned char command_code;
  size_t prefix_address_size;
  size_t reply_address_unpadded_size;

  assert(header);
  assert(serialized_size);

  packet_type = RMAP_PACKET_TYPE_COMMAND;
  command_code = 0;
  prefix_address_size = 0;
  reply_address_unpadded_size = 0;
  if (header->type == RMAP_TYPE_COMMAND) {
    prefix_address_size = header->t.command.target_address.length;
    packet_type = RMAP_PACKET_TYPE_COMMAND;
    command_code = header->t.command.command_codes;
    reply_address_unpadded_size = header->t.command.reply_address.length;
  } else if (header->type == RMAP_TYPE_WRITE_REPLY) {
    reply_address_unpadded_size = header->t.write_reply.reply_address.length;
    prefix_address_size = reply_address_unpadded_size;
    packet_type = RMAP_PACKET_TYPE_REPLY;
    command_code = header->t.write_reply.command_codes;
  } else {
    assert(header->type == RMAP_TYPE_READ_REPLY);
    reply_address_unpadded_size = header->t.read_reply.reply_address.length;
    prefix_address_size = reply_address_unpadded_size;
    packet_type = RMAP_PACKET_TYPE_REPLY;
    command_code = header->t.read_reply.command_codes;
  }

  status = make_instruction(
      &instruction,
      packet_type,
      command_code,
      reply_address_unpadded_size);
  if (status != RMAP_OK) {
    return status;
  }

  *serialized_size = prefix_address_size + calculate_header_size(instruction);

  return RMAP_OK;
}

rmap_status_t rmap_header_serialize(
    size_t *const serialized_size,
    unsigned char *const data,
    const size_t data_size,
    const rmap_send_header_t *const header)
{
  bool is_unused_command_code;
  rmap_status_t rmap_status;
  size_t serialized_size_tmp;

  assert(header);
  assert(serialized_size);

  is_unused_command_code = false;

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
      return RMAP_UNUSED_PACKET_TYPE;
  }
  switch (rmap_status) {
    case RMAP_NOT_ENOUGH_SPACE:
    case RMAP_REPLY_ADDRESS_TOO_LONG:
    case RMAP_DATA_LENGTH_TOO_BIG:
    case RMAP_NO_REPLY:
    case RMAP_INVALID_COMMAND_CODE:
      return rmap_status;

    case RMAP_UNUSED_COMMAND_CODE:
      is_unused_command_code = true;
      break;

    default:
      assert(rmap_status == RMAP_OK);
      break;
  }

  *serialized_size = serialized_size_tmp;

  if (is_unused_command_code) {
    return RMAP_UNUSED_COMMAND_CODE;
  }
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
  bool is_unused_command_code;

  assert(serialized_offset);
  assert(serialized_size);
  assert(data);
  assert(header);

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
        rmap_status == RMAP_REPLY_ADDRESS_TOO_LONG ||
        rmap_status == RMAP_UNUSED_PACKET_TYPE);
    return rmap_status;
  }

  if (calculated_header_serialized_size > payload_offset) {
    return RMAP_NOT_ENOUGH_SPACE;
  }

  is_unused_command_code = false;

  rmap_status = rmap_header_serialize(
      &header_serialized_size,
      data + payload_offset - calculated_header_serialized_size,
      payload_offset,
      header);
  switch (rmap_status) {
    case RMAP_REPLY_ADDRESS_TOO_LONG:
    case RMAP_DATA_LENGTH_TOO_BIG:
      return rmap_status;

    case RMAP_UNUSED_COMMAND_CODE:
      is_unused_command_code = true;
      break;

    default:
      assert(rmap_status == RMAP_OK);
      break;
  }
  assert(header_serialized_size == calculated_header_serialized_size);

  data[payload_offset + payload_size] =
    rmap_crc_calculate(data + payload_offset, payload_size);

  *serialized_offset = payload_offset - header_serialized_size;
  *serialized_size = header_serialized_size + payload_size + 1;

  if (is_unused_command_code) {
    return RMAP_UNUSED_COMMAND_CODE;
  }
  return RMAP_OK;
}

rmap_status_t rmap_header_deserialize(
    size_t *const serialized_size,
    rmap_receive_header_t *const header,
    const unsigned char *const data,
    const size_t data_size)
{
  rmap_status_t status;
  unsigned char command_code;
  bool is_reply_without_reply;

  assert(serialized_size);
  assert(header);
  assert(data);

  status = verify_header(data, data_size);
  switch (status) {
    case RMAP_INCOMPLETE_HEADER:
    case RMAP_NO_RMAP_PROTOCOL:
    case RMAP_HEADER_CRC_ERROR:
      /* Header cannot or should not be deserialized. */
      return status;

    default:
      /* Header still counts as "verified" if it has an unused packet type or
       * unused command code, in order to allow sending error replies for these
       * cases.
       */
      break;
  }

  const uint8_t instruction = rmap_get_instruction(data);

  /* Other errors currently take precedence over reply-without-reply, so avoid
   * reporting it directly.
   */
  is_reply_without_reply = false;
  if (!rmap_is_instruction_command(instruction) &&
      !rmap_is_instruction_with_reply(instruction)) {
    is_reply_without_reply = true;
  }

  command_code = 0;
  if (rmap_is_instruction_write(instruction)) {
    command_code |= RMAP_COMMAND_CODE_WRITE;
  }
  if (rmap_is_instruction_verify_data_before_write(instruction)) {
    command_code |= RMAP_COMMAND_CODE_VERIFY;
  }
  if (rmap_is_instruction_with_reply(instruction)) {
    command_code |= RMAP_COMMAND_CODE_REPLY;
  }
  if (rmap_is_instruction_increment_address(instruction)) {
    command_code |= RMAP_COMMAND_CODE_INCREMENT;
  }

  *serialized_size = calculate_header_size(instruction);

  if (rmap_is_instruction_command(instruction)) {
    header->type = RMAP_TYPE_COMMAND;
    header->t.command.target_logical_address =
      rmap_get_target_logical_address(data);
    header->t.command.command_codes = command_code;
    header->t.command.key = rmap_get_key(data);

    status = rmap_get_reply_address(
        header->t.command.reply_address.data,
        &header->t.command.reply_address.length,
        sizeof(header->t.command.reply_address.data),
        data);
    if (status != RMAP_OK) {
      return status;
    }

    header->t.command.initiator_logical_address =
      rmap_get_initiator_logical_address(data);
    header->t.command.transaction_identifier =
      rmap_get_transaction_identifier(data);
    header->t.command.extended_address = rmap_get_extended_address(data);
    header->t.command.address = rmap_get_address(data);

    header->t.command.data_length = rmap_get_header_data_length(data);

    if (!rmap_is_instruction_write(instruction) &&
        data_size > *serialized_size) {
      /* Data characters in read command are invalid. */
      return RMAP_ECSS_TOO_MUCH_DATA;
    }

    if (rmap_is_instruction_unused_packet_type(instruction)) {
      return RMAP_UNUSED_PACKET_TYPE;
    }

    if (is_reply_without_reply) {
      return RMAP_INVALID_REPLY;
    }

    if (rmap_is_instruction_unused_command_code(instruction)) {
      return RMAP_UNUSED_COMMAND_CODE;
    }

    return RMAP_OK;
  }

  /* Reply packet type. */

  if (rmap_is_instruction_write(instruction)) {
    header->type = RMAP_TYPE_WRITE_REPLY;
    header->t.write_reply.initiator_logical_address =
      rmap_get_initiator_logical_address(data);
    header->t.write_reply.command_codes = command_code;
    header->t.write_reply.status = rmap_get_status(data);
    header->t.write_reply.target_logical_address =
      rmap_get_target_logical_address(data);
    header->t.write_reply.transaction_identifier =
      rmap_get_transaction_identifier(data);

    if (data_size > RMAP_WRITE_REPLY_HEADER_STATIC_SIZE) {
      /* Data characters in write reply are invalid. */
      return RMAP_ECSS_TOO_MUCH_DATA;
    }

    // TODO: Should this be "packet error" or "invalid reply" only?
    if (rmap_is_instruction_unused_packet_type(instruction)) {
      return RMAP_UNUSED_PACKET_TYPE;
    }

    if (is_reply_without_reply ||
        rmap_is_instruction_unused_command_code(instruction)) {
      return RMAP_UNUSED_COMMAND_CODE;
    }

    return RMAP_OK;
  }

  /* Read reply. */

  header->type = RMAP_TYPE_READ_REPLY;
  header->t.read_reply.initiator_logical_address =
    rmap_get_initiator_logical_address(data);
  header->t.read_reply.command_codes = command_code;
  header->t.read_reply.status = rmap_get_status(data);
  header->t.read_reply.target_logical_address =
    rmap_get_target_logical_address(data);
  header->t.read_reply.transaction_identifier =
    rmap_get_transaction_identifier(data);
  header->t.read_reply.data_length = rmap_get_header_data_length(data);

  // TODO: Should this be "packet error" or "invalid reply" only?
  if (rmap_is_instruction_unused_packet_type(instruction)) {
    return RMAP_UNUSED_PACKET_TYPE;
  }

  if (rmap_is_instruction_unused_command_code(instruction)) {
    return RMAP_UNUSED_COMMAND_CODE;
  }

  return RMAP_OK;
}

const char *rmap_status_text(const rmap_status_t status)
{
  switch (status) {
    case RMAP_OK:
      return "RMAP_OK";

    case RMAP_NOT_ENOUGH_SPACE:
      return "RMAP_NOT_ENOUGH_SPACE";

    case RMAP_REPLY_ADDRESS_TOO_LONG:
      return "RMAP_REPLY_ADDRESS_TOO_LONG";

    case RMAP_DATA_LENGTH_TOO_BIG:
      return "RMAP_DATA_LENGTH_TOO_BIG";

    case RMAP_INCOMPLETE_HEADER:
      return "RMAP_INCOMPLETE_HEADER";

    case RMAP_NO_RMAP_PROTOCOL:
      return "RMAP_NO_RMAP_PROTOCOL";

    case RMAP_HEADER_CRC_ERROR:
      return "RMAP_HEADER_CRC_ERROR";

    case RMAP_NO_REPLY:
      return "RMAP_NO_REPLY";

    case RMAP_UNUSED_PACKET_TYPE:
      return "RMAP_UNUSED_PACKET_TYPE";

    case RMAP_INVALID_PACKET_TYPE:
      return "RMAP_INVALID_PACKET_TYPE";

    case RMAP_UNUSED_COMMAND_CODE:
      return "RMAP_UNUSED_COMMAND_CODE";

    case RMAP_INVALID_COMMAND_CODE:
      return "RMAP_INVALID_COMMAND_CODE";

    case RMAP_ECSS_INVALID_DATA_CRC:
      return "RMAP_ECSS_INVALID_DATA_CRC";

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
