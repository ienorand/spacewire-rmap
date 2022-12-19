#include "rmap.h"

#include <assert.h>
#include <string.h>

struct common_header {
  uint8_t logical_address;
  uint8_t protocol_identifier;
  uint8_t instruction;
};

struct command_header_first_static_part {
  uint8_t target_logical_address;
  uint8_t protocol_identifier;
  uint8_t instruction;
  uint8_t key;
};

struct command_header_second_static_part {
  uint8_t initiator_logical_address;
  uint8_t transaction_identifier[2];
  uint8_t extended_address;
  uint8_t address[4];
  uint8_t data_length[3];
  uint8_t crc;
};

struct reply_common_header {
  uint8_t initiator_logical_address;
  uint8_t protocol_identifier;
  uint8_t instruction;
  uint8_t status;
  uint8_t target_logical_address;
  uint8_t transaction_identifier[2];
};

struct read_or_rmw_reply_header {
  uint8_t initiator_logical_address;
  uint8_t protocol_identifier;
  uint8_t instruction;
  uint8_t status;
  uint8_t target_logical_address;
  uint8_t transaction_identifier[2];
  uint8_t reserved;
  uint8_t data_length[3];
  uint8_t crc;
};

uint8_t rmap_get_protocol(const void *const header)
{
  const struct common_header *const common = header;
  return common->protocol_identifier;
}

void rmap_set_protocol(void *const header)
{
  struct common_header *const common = header;
  common->protocol_identifier = 1;
}

uint8_t rmap_get_instruction(const void *const header)
{
  const struct common_header *const common = header;
  return common->instruction;
}

void rmap_set_instruction(void *const header, const uint8_t instruction)
{
  struct common_header *const common = header;
  common->instruction = instruction;
}

bool rmap_is_instruction_command(const uint8_t instruction)
{
  return instruction &
    (RMAP_PACKET_TYPE_COMMAND << RMAP_INSTRUCTION_PACKET_TYPE_SHIFT);
}

bool rmap_is_command(const void *const header)
{
  return rmap_is_instruction_command(rmap_get_instruction(header));
}

bool rmap_is_instruction_unused_packet_type(const uint8_t instruction)
{
  return instruction & (0x2 << RMAP_INSTRUCTION_PACKET_TYPE_SHIFT);
}

bool rmap_is_unused_packet_type(const void *const header)
{
  return rmap_is_instruction_unused_packet_type(rmap_get_instruction(header));
}

bool rmap_is_instruction_write(const uint8_t instruction)
{
  return instruction &
    (RMAP_COMMAND_CODE_WRITE << RMAP_INSTRUCTION_COMMAND_CODE_SHIFT);
}

bool rmap_is_write(const void *const header)
{
  return rmap_is_instruction_write(rmap_get_instruction(header));
}

bool rmap_is_instruction_verify_data_before_write(const uint8_t instruction)
{
  return instruction &
    (RMAP_COMMAND_CODE_VERIFY << RMAP_INSTRUCTION_COMMAND_CODE_SHIFT);
}

bool rmap_is_verify_data_before_write(const void *const header)
{
  return
    rmap_is_instruction_verify_data_before_write(rmap_get_instruction(header));
}

bool rmap_is_instruction_with_reply(const uint8_t instruction)
{
  return instruction &
    (RMAP_COMMAND_CODE_REPLY << RMAP_INSTRUCTION_COMMAND_CODE_SHIFT);
}

bool rmap_is_with_reply(const void *const header)
{
  return rmap_is_instruction_with_reply(rmap_get_instruction(header));
}

bool rmap_is_instruction_increment_address(const uint8_t instruction)
{
  return instruction &
    (RMAP_COMMAND_CODE_INCREMENT << RMAP_INSTRUCTION_COMMAND_CODE_SHIFT);
}

bool rmap_is_increment_address(const void *const header)
{
  return rmap_is_instruction_increment_address(rmap_get_instruction(header));
}

bool rmap_is_instruction_rmw(const uint8_t instruction)
{
  return !rmap_is_instruction_write(instruction) &&
    rmap_is_instruction_verify_data_before_write(instruction) &&
    rmap_is_instruction_with_reply(instruction) &&
    rmap_is_instruction_increment_address(instruction);
}

bool rmap_is_rmw(const void *const header)
{
  return rmap_is_instruction_rmw(rmap_get_instruction(header));
}

bool rmap_is_instruction_unused_command_code(const uint8_t instruction)
{
  const int command_code =
    (instruction & RMAP_INSTRUCTION_COMMAND_CODE_MASK) >>
    RMAP_INSTRUCTION_COMMAND_CODE_SHIFT;

  switch (command_code) {
    case 0x0:
    case RMAP_COMMAND_CODE_INCREMENT:
    case RMAP_COMMAND_CODE_VERIFY:
    case (RMAP_COMMAND_CODE_VERIFY | RMAP_COMMAND_CODE_INCREMENT):
    case (RMAP_COMMAND_CODE_VERIFY | RMAP_COMMAND_CODE_REPLY):
      return true;

    default:
      break;
  }

  return false;
}

bool rmap_is_unused_command_code(const void *const header)
{
  return rmap_is_instruction_unused_command_code(rmap_get_instruction(header));
}

uint8_t rmap_get_key(const void *const header)
{
  const struct command_header_first_static_part *const first_static_part =
    header;
  return first_static_part->key;
}

void rmap_set_key(void *const header, const uint8_t key)
{
  struct command_header_first_static_part *const first_static_part = header;
  first_static_part->key = key;
}

uint8_t rmap_get_status(const void *const header)
{
  const struct reply_common_header  *const reply_common = header;
  return reply_common->status;
}

void rmap_set_status(void *const header, const uint8_t status)
{
  struct reply_common_header *const reply_common = header;
  reply_common->status = status;
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

enum rmap_status rmap_get_reply_address(
    uint8_t *reply_address,
    size_t *const reply_address_size,
    const size_t reply_address_max_size,
    const void *const header)
{
  const unsigned char *reply_address_padded;

  const size_t reply_address_padded_size =
    calculate_reply_address_padded_size(rmap_get_instruction(header));
  const unsigned char *const header_bytes = header;
  reply_address_padded =
    header_bytes + sizeof(struct command_header_first_static_part);

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
    void *const header,
    const uint8_t *const reply_address,
    const size_t reply_address_size)
{
  unsigned char *reply_address_padded;

  unsigned char *const header_bytes = header;
  reply_address_padded =
    header_bytes + sizeof(struct command_header_first_static_part);

  const size_t padding_size =
    calculate_reply_address_padded_size(rmap_get_instruction(header)) -
    reply_address_size;
  memset(reply_address_padded, 0x00, padding_size);

  memcpy(
      reply_address_padded + padding_size,
      reply_address,
      reply_address_size);
}

uint8_t rmap_get_target_logical_address(const void *const header)
{
  if (rmap_is_command(header)) {
    const struct command_header_first_static_part *const first_static_part =
      header;
    return first_static_part->target_logical_address;
  }

  /* Reply. */
  const struct reply_common_header *const reply_common = header;
  return reply_common->target_logical_address;
}

void rmap_set_target_logical_address(
    void *const header,
    const uint8_t target_logical_address)
{
  if (rmap_is_command(header)) {
    struct command_header_first_static_part *const first_static_part = header;
    first_static_part->target_logical_address = target_logical_address;
    return;
  }

  /* Reply. */
  struct reply_common_header *const reply_common = header;
  reply_common->target_logical_address = target_logical_address;
}

static struct command_header_second_static_part
*get_command_header_second_static_part(void *const header)
{
  unsigned char *const header_bytes = header;
  size_t reply_address_padded_size =
    calculate_reply_address_padded_size(rmap_get_instruction(header));
  void *const second_static_part_raw =
    header_bytes + sizeof(struct command_header_first_static_part) +
    reply_address_padded_size;
  return second_static_part_raw;
}

static const struct command_header_second_static_part
*get_command_header_second_static_part_const(const void *const header)
{
  const unsigned char *const header_bytes = header;
  const size_t reply_address_padded_size =
    calculate_reply_address_padded_size(rmap_get_instruction(header));
  const void *const second_static_part_raw =
    header_bytes + sizeof(struct command_header_first_static_part) +
    reply_address_padded_size;
  return second_static_part_raw;
}

uint8_t rmap_get_initiator_logical_address(const void *const header)
{
  if (rmap_is_command(header)) {
    return get_command_header_second_static_part_const(header)->
      initiator_logical_address;
  }

  /* Reply. */
  const struct reply_common_header *const reply_common = header;
  return reply_common->initiator_logical_address;
}

void rmap_set_initiator_logical_address(
    void *const header,
    const uint8_t initiator_logical_address)
{
  if (rmap_is_command(header)) {
    get_command_header_second_static_part(header)->initiator_logical_address =
      initiator_logical_address;
    return;
  }

  /* Reply. */
  struct reply_common_header *const reply_common = header;
  reply_common->initiator_logical_address = initiator_logical_address;
}

uint16_t rmap_get_transaction_identifier(const void *const header)
{
  if (rmap_is_command(header)) {
    const struct command_header_second_static_part *const second_static_part =
      get_command_header_second_static_part_const(header);
    return (second_static_part->transaction_identifier[0] << 8) |
      (second_static_part->transaction_identifier[1] << 0);
  }

  const struct reply_common_header *const reply_common = header;
    return (reply_common->transaction_identifier[0] << 8) |
      (reply_common->transaction_identifier[1] << 0);
}

void rmap_set_transaction_identifier(
    void *const header,
    const uint16_t transaction_identifier)
{
  if (rmap_is_command(header)) {
    struct command_header_second_static_part *const second_static_part =
      get_command_header_second_static_part(header);
    second_static_part->transaction_identifier[0] =
      transaction_identifier >> 8;
    second_static_part->transaction_identifier[1] =
      transaction_identifier & 0xFF;
    return;
  }

  struct reply_common_header *const reply_common = header;
  reply_common->transaction_identifier[0] = transaction_identifier >> 8;
  reply_common->transaction_identifier[1] = transaction_identifier & 0xFF;
}

void rmap_set_reserved(void *const header)
{
  struct read_or_rmw_reply_header *const read_or_rmw_reply = header;
  read_or_rmw_reply->reserved = 0;
}

uint8_t rmap_get_extended_address(const void *const header)
{
  return get_command_header_second_static_part_const(header)->extended_address;
}

void rmap_set_extended_address(
    void *const header,
    const uint8_t extended_address)
{
  get_command_header_second_static_part(header)->extended_address =
    extended_address;
}

uint32_t rmap_get_address(const void *const header)
{
  const struct command_header_second_static_part *const second_static_part =
    get_command_header_second_static_part_const(header);
  return ((uint32_t)second_static_part->address[0] << 24) |
    ((uint32_t)second_static_part->address[1] << 16) |
    (second_static_part->address[2] << 8) |
    (second_static_part->address[3] << 0);
}

void rmap_set_address(void *const header, const uint32_t address)
{
  struct command_header_second_static_part *const second_static_part =
    get_command_header_second_static_part(header);
  second_static_part->address[0] = (address >> 24) & 0xFF;
  second_static_part->address[1] = (address >> 16) & 0xFF;
  second_static_part->address[2] = (address >> 8) & 0xFF;
  second_static_part->address[3] = (address >> 0) & 0xFF;
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

size_t rmap_calculate_header_size(const void *const header)
{
  return calculate_header_size(rmap_get_instruction(header));
}

uint32_t rmap_get_data_length(const void *const header)
{
  const uint8_t instruction = rmap_get_instruction(header);

  if (rmap_is_instruction_command(instruction)) {
    const struct command_header_second_static_part *const second_static_part =
      get_command_header_second_static_part_const(header);
    return ((uint32_t)second_static_part->data_length[0] << 16) |
      (second_static_part->data_length[1] << 8) |
      (second_static_part->data_length[2] << 0);
  }

  /* Reply. */

  if (rmap_is_instruction_write(instruction)) {
    /* Write reply has no data. */
    return 0;
  }

  const struct read_or_rmw_reply_header *const read_or_rmw_reply = header;
  return ((uint32_t)read_or_rmw_reply->data_length[0] << 16) |
    (read_or_rmw_reply->data_length[1] << 8) |
    (read_or_rmw_reply->data_length[2] << 0);
}

void rmap_set_data_length(void *const header, const uint32_t data_length)
{
  const uint8_t instruction = rmap_get_instruction(header);

  if (rmap_is_instruction_command(instruction)) {
    struct command_header_second_static_part *const second_static_part =
      get_command_header_second_static_part(header);
    second_static_part->data_length[0] = (data_length >> 16) & 0xFF;
    second_static_part->data_length[1] = (data_length >> 8) & 0xFF;
    second_static_part->data_length[2] = (data_length >> 0) & 0xFF;
    return;
  }

  /* Reply. */

  if (rmap_is_instruction_write(instruction)) {
    /* Write reply has no data. */
    return;
  }

  struct read_or_rmw_reply_header *const read_or_rmw_reply = header;
  read_or_rmw_reply->data_length[0] = (data_length >> 16) & 0xFF;
  read_or_rmw_reply->data_length[1] = (data_length >> 8) & 0xFF;
  read_or_rmw_reply->data_length[2] = (data_length >> 0) & 0xFF;
}

void rmap_calculate_and_set_header_crc(void *const header)
{
  const size_t header_size = rmap_calculate_header_size(header);
  unsigned char *const header_bytes = header;
  header_bytes[header_size - 1] = rmap_crc_calculate(header, header_size - 1);
}

enum rmap_status rmap_verify_header_integrity(
    const void *const header,
    const size_t size)
{
  size_t header_size;

  if (size < RMAP_HEADER_MINIMUM_SIZE) {
    return RMAP_INCOMPLETE_HEADER;
  }

  if (rmap_get_protocol(header) != 1) {
    return RMAP_NO_RMAP_PROTOCOL;
  }

  header_size = rmap_calculate_header_size(header);

  if (size < header_size) {
    return RMAP_INCOMPLETE_HEADER;
  }

  const uint8_t crc = rmap_crc_calculate(header, header_size);
  /* If the received CRC is included in the CRC calculation, the result should
   * be 0.
   */
  if (crc != 0) {
    return RMAP_HEADER_CRC_ERROR;
  }

  return RMAP_OK;
}

enum rmap_status rmap_verify_header_instruction(const void *const header)
{
  if (!rmap_is_command(header)) {
    if (rmap_is_unused_packet_type(header)) {
      /* Reply packet type with packet type reserved bit set */
      return RMAP_UNUSED_PACKET_TYPE;
    }

    if (!rmap_is_with_reply(header)) {
      /* Reply packet type without command code reply bit set. */
      return RMAP_NO_REPLY;
    }
  }

  if (rmap_is_unused_packet_type(header)) {
    return RMAP_UNUSED_PACKET_TYPE;
  }

  if (rmap_is_unused_command_code(header)) {
    return RMAP_UNUSED_COMMAND_CODE;
  }

  return RMAP_OK;
}

static bool has_data_field(const void *const packet)
{
  if (rmap_is_rmw(packet)) {
    return true;
  }

  if (rmap_is_command(packet) && rmap_is_write(packet)) {
    return true;
  }

  if (!rmap_is_command(packet) && !rmap_is_write(packet)) {
    return true;
  }

  return false;
}

enum rmap_status rmap_verify_data(const void *const packet, const size_t size)
{
  if (!has_data_field(packet)) {
    return RMAP_NO_DATA;
  }

  const size_t data_offset = rmap_calculate_header_size(packet);
  const size_t data_length = rmap_get_data_length(packet);

  if (rmap_is_rmw(packet)) {
    if (rmap_is_command(packet)) {
      switch (data_length) {
        case 0:
        case 2:
        case 4:
        case 6:
        case 8:
          break;

        default:
          return RMAP_RMW_DATA_LENGTH_ERROR;
      }
    } else {
      /* RMW reply. */
      switch (data_length) {
        case 0:
        case 1:
        case 2:
        case 3:
        case 4:
          break;

        default:
          return RMAP_RMW_DATA_LENGTH_ERROR;
      }
    }
  }

  if (size < data_offset + data_length + 1) {
    return RMAP_INSUFFICIENT_DATA;
  }

  if (size > data_offset + data_length + 1) {
    return RMAP_TOO_MUCH_DATA;
  }

  const unsigned char *const packet_bytes = packet;
  const uint8_t data_crc =
    rmap_crc_calculate(packet_bytes + data_offset, data_length + 1);
  /* If the crc is included in the crc calculation, the result should be 0. */
  if (data_crc != 0) {
    return RMAP_INVALID_DATA_CRC;
  }

  return RMAP_OK;
}

/** Make an RMAP instruction field.
 *
 * Creating invalid instruction fields with unused packet types or unused
 * command codes is supported in order to allow creating invalid RMAP headers
 * for testing purposes.
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
static enum rmap_status make_instruction(
    uint8_t *const instruction,
    const enum rmap_packet_type packet_type,
    const int command_code,
    const size_t reply_address_unpadded_size)
{
  *instruction = 0;

  if (packet_type < 0 || packet_type > RMAP_PACKET_TYPE_COMMAND_RESERVED) {
    return RMAP_INVALID_PACKET_TYPE;
  }

  *instruction |= packet_type << RMAP_INSTRUCTION_PACKET_TYPE_SHIFT;

  const int all_command_codes =
    RMAP_COMMAND_CODE_WRITE |
    RMAP_COMMAND_CODE_VERIFY |
    RMAP_COMMAND_CODE_REPLY |
    RMAP_COMMAND_CODE_INCREMENT;
  if (command_code < 0 || command_code > all_command_codes) {
    return RMAP_INVALID_COMMAND_CODE;
  }

  *instruction |= command_code << RMAP_INSTRUCTION_COMMAND_CODE_SHIFT;


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

enum rmap_status rmap_initialize_header(
    void *const header,
    const size_t max_size,
    const enum rmap_packet_type packet_type,
    const int command_code,
    const size_t reply_address_unpadded_size)
{
  uint8_t instruction;

  const enum rmap_status status = make_instruction(
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

enum rmap_status rmap_initialize_header_before(
    size_t *const header_offset,
    void *const raw,
    const size_t data_offset,
    const enum rmap_packet_type packet_type,
    const int command_code,
    const size_t reply_address_unpadded_size)
{
  enum rmap_status status;
  uint8_t instruction;

  status = make_instruction(
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

  const size_t header_size = calculate_header_size(instruction);

  if (header_size > data_offset) {
    return RMAP_NOT_ENOUGH_SPACE;
  }

  *header_offset = data_offset - header_size;

  unsigned char *const raw_bytes = raw;
  rmap_set_protocol(raw_bytes + *header_offset);
  rmap_set_instruction(raw_bytes + *header_offset, instruction);

  return RMAP_OK;
}

enum rmap_status rmap_create_success_reply_from_command(
    void *const raw,
    size_t *const reply_header_offset,
    const size_t max_size,
    const void *const command_header)
{
  uint8_t reply_address[RMAP_REPLY_ADDRESS_LENGTH_MAX];
  size_t reply_address_size;

  if (!rmap_is_with_reply(command_header)) {
    return RMAP_NO_REPLY;
  }

  /* Clear command bit and reserved bit, a correct reply should have reserved
   * bit clear, even if the command had it set.
   */
  const uint8_t instruction =
    rmap_get_instruction(command_header) & ~RMAP_INSTRUCTION_PACKET_TYPE_MASK;

  const enum rmap_status status = rmap_get_reply_address(
        reply_address,
        &reply_address_size,
        sizeof(reply_address),
        command_header);
  assert(status == RMAP_OK);
  /* Avoid unused warning if asserts are disabled. */
  (void)status;

  if (reply_address_size + calculate_header_size(instruction) > max_size) {
    return RMAP_NOT_ENOUGH_SPACE;
  }

  *reply_header_offset = reply_address_size;

  memcpy(raw, reply_address, reply_address_size);

  unsigned char *const raw_bytes = raw;
  void *const reply_header = raw_bytes + reply_address_size;

  rmap_set_protocol(reply_header);
  rmap_set_instruction(reply_header, instruction);

  rmap_set_initiator_logical_address(
      reply_header,
      rmap_get_initiator_logical_address(command_header));
  rmap_set_status(reply_header, RMAP_STATUS_FIELD_CODE_SUCCESS);
  rmap_set_target_logical_address(
      reply_header,
      rmap_get_target_logical_address(command_header));
  rmap_set_transaction_identifier(
      reply_header,
      rmap_get_transaction_identifier(command_header));

  if (!rmap_is_write(command_header)) {
    /* Read reply or RMW reply. */
    rmap_set_reserved(reply_header);
    if (rmap_is_rmw(command_header)) {
      rmap_set_data_length(
          reply_header,
          rmap_get_data_length(command_header) / 2);
    } else {
      /* Read reply. */
      rmap_set_data_length(
          reply_header,
          rmap_get_data_length(command_header));
    }
  }

  rmap_calculate_and_set_header_crc(reply_header);

  return RMAP_OK;
}

enum rmap_status rmap_create_success_reply_from_command_before(
    void *const raw,
    size_t *const reply_offset,
    size_t *const reply_header_offset,
    const size_t data_offset,
    const void *const command_header)
{
  enum rmap_status status;
  uint8_t reply_address[RMAP_REPLY_ADDRESS_LENGTH_MAX];
  size_t reply_address_size;

  const uint8_t instruction =
    rmap_get_instruction(command_header) & ~RMAP_INSTRUCTION_PACKET_TYPE_MASK;

  status = rmap_get_reply_address(
        reply_address,
        &reply_address_size,
        sizeof(reply_address),
        command_header);
  assert(status == RMAP_OK);
  /* Avoid unused warning if asserts are disabled. */
  (void)status;

  const size_t size = reply_address_size + calculate_header_size(instruction);

  if (size > data_offset) {
    return RMAP_NOT_ENOUGH_SPACE;
  }

  uint8_t *const raw_bytes = raw;
  status = rmap_create_success_reply_from_command(
      raw_bytes + data_offset - size,
      reply_header_offset,
      size,
      command_header);
  if (status != RMAP_OK) {
    /* RMAP_NOT_ENOUGH_SPACE should not be possible since checked above. */
    assert(status == RMAP_NO_REPLY);
    return RMAP_NO_REPLY;
  }

  *reply_offset = data_offset - size;
  *reply_header_offset = *reply_offset + reply_address_size;

  return RMAP_OK;
}

const char *rmap_status_text(const int status)
{
  switch (status) {
    case RMAP_STATUS_FIELD_CODE_SUCCESS:
      assert((int)RMAP_OK == (int)RMAP_STATUS_FIELD_CODE_SUCCESS);
      return "RMAP_STATUS_FIELD_CODE_SUCCESS/RMAP_OK";

    case RMAP_STATUS_FIELD_CODE_GENERAL_ERROR_CODE:
      return "RMAP_STATUS_FIELD_CODE_GENERAL_ERROR_CODE";

    case RMAP_STATUS_FIELD_CODE_UNUSED_PACKET_TYPE_OR_COMMAND_CODE:
      return "RMAP_STATUS_FIELD_CODE_UNUSED_PACKET_TYPE_OR_COMMAND_CODE";

    case RMAP_STATUS_FIELD_CODE_INVALID_KEY:
      return "RMAP_STATUS_FIELD_CODE_INVALID_KEY";

    case RMAP_STATUS_FIELD_CODE_INVALID_DATA_CRC:
      return "RMAP_STATUS_FIELD_CODE_INVALID_DATA_CRC";

    case RMAP_STATUS_FIELD_CODE_EARLY_EOP:
      return "RMAP_STATUS_FIELD_CODE_EARLY_EOP";

    case RMAP_STATUS_FIELD_CODE_TOO_MUCH_DATA:
      return "RMAP_STATUS_FIELD_CODE_TOO_MUCH_DATA";

    case RMAP_STATUS_FIELD_CODE_EEP:
      return "RMAP_STATUS_FIELD_CODE_EEP";

    case RMAP_STATUS_FIELD_CODE_VERIFY_BUFFER_OVERRUN:
      return "RMAP_STATUS_FIELD_CODE_VERIFY_BUFFER_OVERRUN";

    case RMAP_STATUS_FIELD_CODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED:
      return "RMAP_STATUS_FIELD_CODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED";

    case RMAP_STATUS_FIELD_CODE_RMW_DATA_LENGTH_ERROR:
      return "RMAP_STATUS_FIELD_CODE_RMW_DATA_LENGTH_ERROR";

    case RMAP_STATUS_FIELD_CODE_INVALID_TARGET_LOGICAL_ADDRESS:
      return "RMAP_STATUS_FIELD_CODE_INVALID_TARGET_LOGICAL_ADDRESS";

    case RMAP_INCOMPLETE_HEADER:
      return "RMAP_INCOMPLETE_HEADER";

    case RMAP_NO_RMAP_PROTOCOL:
      return "RMAP_NO_RMAP_PROTOCOL";

    case RMAP_HEADER_CRC_ERROR:
      return "RMAP_HEADER_CRC_ERROR";

    case RMAP_UNUSED_PACKET_TYPE:
      return "RMAP_UNUSED_PACKET_TYPE";

    case RMAP_UNUSED_COMMAND_CODE:
      return "RMAP_UNUSED_COMMAND_CODE";

    case RMAP_NO_REPLY:
      return "RMAP_NO_REPLY";

    case RMAP_NO_DATA:
      return "RMAP_NO_DATA";

    case RMAP_INSUFFICIENT_DATA:
      return "RMAP_INSUFFICIENT_DATA";

    case RMAP_TOO_MUCH_DATA:
      return "RMAP_TOO_MUCH_DATA";

    case RMAP_INVALID_DATA_CRC:
      return "RMAP_INVALID_DATA_CRC";

    case RMAP_RMW_DATA_LENGTH_ERROR:
      return "RMAP_RMW_DATA_LENGTH_ERROR";

    case RMAP_INVALID_PACKET_TYPE:
      return "RMAP_INVALID_PACKET_TYPE";

    case RMAP_INVALID_COMMAND_CODE:
      return "RMAP_INVALID_COMMAND_CODE";

    case RMAP_REPLY_ADDRESS_TOO_LONG:
      return "RMAP_REPLY_ADDRESS_TOO_LONG";

    case RMAP_NOT_ENOUGH_SPACE:
      return "RMAP_NOT_ENOUGH_SPACE";

    default:
      return "INVALID_STATUS";
  }
}

uint8_t rmap_crc_calculate(const void *const data, const size_t data_size)
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

  const unsigned char *const data_bytes = data;
  crc = 0;
  for (size_t i = 0; i < data_size; ++i) {
    crc = crc_lookup_table[crc ^ data_bytes[i]];
  }

  return crc;
}
