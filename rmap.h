#ifndef RMAP_H
#define RMAP_H

#include <stdint.h>
#include <stddef.h>

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

/** Representation of an RMAP header type. */
typedef enum {
  RMAP_TYPE_COMMAND,
  RMAP_TYPE_WRITE_REPLY,
  RMAP_TYPE_READ_REPLY
} rmap_type_t;

/** Representation of RMAP command codes. */
enum {
  RMAP_COMMAND_CODE_WRITE = 1 << 0,
  RMAP_COMMAND_CODE_VERIFY = 1 << 1,
  RMAP_COMMAND_CODE_REPLY = 1 << 2,
  RMAP_COMMAND_CODE_INCREMENT = 1 << 3
};

/** RMAP status and error constants.
 *
 * RMAP status and error constants which can be returned by the RMAP functions.
 *
 * Constants which corresponds to standardized errors in the ECSS RMAP
 * specification use a "RMAP_ECSS_" prefix.
 */
typedef enum {
  /** Success. */
  RMAP_OK,

  /** Not enough space in provided parameters to complete operation.
   *
   * This is only used to indicate errors by the library function caller, not
   * errors that can occur as part of the protocol operation.
   *
   * For example, this can indicate that the provided destination data is not
   * large enough to fit the RMAP header which is being serialized, or that the
   * provided destination data for the reply address is not large enough to fit
   * the reply address being copied.
   */
  RMAP_NOT_ENOUGH_SPACE,

  /** The provided reply address is larger than 12 bytes. */
  RMAP_REPLY_ADDRESS_TOO_LONG,

  /** The provided data length is unrepresentable in an RMAP data length field.
   *
   * The provided data length is above 16777215 and is not representable in an
   * RMAP data length field.
   */
  RMAP_DATA_LENGTH_TOO_BIG,

  /** The protocol field indicates that this is not an RMAP packet. */
  RMAP_NO_RMAP_PROTOCOL,

  /** The header CRC indicates that errors are present in the header. */
  RMAP_HEADER_CRC_ERROR,

  /** The provided data is not large enough to contain the full RMAP header.
   *
   * This is used to indicates that the provided source data is not large
   * enough to fit the whole RMAP header that is being deserialized.
   */
  RMAP_INCOMPLETE_HEADER,

  /** A reply packet type was combined with a without-reply command code.
   *
   * This is only used to indicate errors by the library function caller, not
   * errors that can occur as part of the protocol operation.
   */
  RMAP_NO_REPLY,

  /** The packet type field has the reserved bit set. */
  RMAP_UNUSED_PACKET_TYPE,

  /** The command field contains a reserved command code. */
  RMAP_UNUSED_COMMAND_CODE,

  /** The provided command code is an unrepresentable command code.
   *
   * This is only used to indicate errors by the library function caller, not
   * errors that can occur as part of the protocol operation.
   */
  RMAP_INVALID_COMMAND_CODE,

  /** The provided data is not large enough to contain the full RMAP packet.
   *
   * This is used to indicates that the provided source data is not large
   * enough to fit the whole RMAP packet that is being deserialized.
   */
  RMAP_EARLY_EOP,

  /** Read-modify-write is not supported. */
  RMAP_READ_MODIFY_WRITE_UNSUPPORTED,

  /** A reply is invalid.
   *
   * This can indicate that either:
   * * An RMAP reply packet was determined to be invalid and should be
   *   discarded (protocol error).
   * * Provided parameters describes an invalid reply header (library function
   *   caller error).
   */
  RMAP_INVALID_REPLY,

  /** The data CRC indicates that errors are present in the data. */
  RMAP_ECSS_INVALID_DATA_CRC,

  /** There is more data than expected.
   *
   * This can indicate that either:
   * * An RMAP packet was determined to contain more data than expected
   *   (protocol error).
   * * An attempt was made to serialize an RMAP read command or write reply
   *   in-place around an existing data field, but these packet types do not
   *   contain a data field (caller error).
   */
  RMAP_ECSS_TOO_MUCH_DATA
} rmap_status_t;

/** Size constants for RMAP packets. */
enum {
  RMAP_COMMAND_HEADER_STATIC_SIZE = 16,
  RMAP_WRITE_REPLY_HEADER_STATIC_SIZE = 8,
  RMAP_READ_REPLY_HEADER_STATIC_SIZE = 12,
  RMAP_HEADER_MINIMUM_SIZE = RMAP_WRITE_REPLY_HEADER_STATIC_SIZE
};

/** Common representation of an RMAP write or read command header for sending.
 */
typedef struct {
  struct {
    const uint8_t *data;
    size_t length;
  } target_address;
  uint8_t target_logical_address;
  unsigned char command_codes;
  uint8_t key;
  struct {
    uint8_t data[12];
    size_t length;
  } reply_address;
  uint8_t initiator_logical_address;
  uint16_t transaction_identifier;
  uint8_t extended_address;
  uint32_t address;
  uint32_t data_length;
} rmap_send_command_header_t;

/** Common representation of an RMAP write and read command header after
 * reception and deserialization.
 */
typedef struct {
  uint8_t target_logical_address;
  unsigned char command_codes;
  uint8_t key;
  struct {
    uint8_t data[12];
    size_t length;
  } reply_address;
  uint8_t initiator_logical_address;
  uint16_t transaction_identifier;
  uint8_t extended_address;
  uint32_t address;
  uint32_t data_length;
} rmap_receive_command_header_t;

/** Representation of an RMAP write reply header for sending. */
typedef struct {
  struct {
    uint8_t data[12];
    size_t length;
  } reply_address;
  uint8_t initiator_logical_address;
  unsigned char command_codes;
  uint8_t status;
  uint8_t target_logical_address;
  uint16_t transaction_identifier;
} rmap_send_write_reply_header_t;

/** Representation of an RMAP write reply header after reception and
 * deserialization.
 */
typedef struct {
  uint8_t initiator_logical_address;
  unsigned char command_codes;
  uint8_t status;
  uint8_t target_logical_address;
  uint16_t transaction_identifier;
} rmap_receive_write_reply_header_t;

/** Representation of an RMAP read reply header for sending. */
typedef struct {
  struct {
    uint8_t data[12];
    size_t length;
  } reply_address;
  uint8_t initiator_logical_address;
  unsigned char command_codes;
  uint8_t status;
  uint8_t target_logical_address;
  uint16_t transaction_identifier;
  uint32_t data_length;
} rmap_send_read_reply_header_t;

/** Representation of an RMAP read reply header after reception and
 * deserialization.
 */
typedef struct {
  uint8_t initiator_logical_address;
  unsigned char command_codes;
  uint8_t status;
  uint8_t target_logical_address;
  uint16_t transaction_identifier;
  uint32_t data_length;
} rmap_receive_read_reply_header_t;

/** Tagged union representation of an RMAP header for sending. */
typedef struct {
  /** Tag indicating the active RMAP header type member. */
  rmap_type_t type;
  union {
    rmap_send_command_header_t command;
    rmap_send_write_reply_header_t write_reply;
    rmap_send_read_reply_header_t read_reply;
  } t;
} rmap_send_header_t;

/** Tagged union representation of an RMAP header after reception and
 * deserialization.
 */
typedef struct {
  /** Tag indicating the active RMAP header type member. */
  rmap_type_t type;
  union {
    rmap_receive_command_header_t command;
    rmap_receive_write_reply_header_t write_reply;
    rmap_receive_read_reply_header_t read_reply;
  } t;
} rmap_receive_header_t;

/** Get the protocol identifier field from a potential RMAP header.
 *
 * @pre @p header must contain at least RMAP_HEADER_MINIMUM_SIZE bytes.
 *
 * @param[in] header Potential RMAP header.
 *
 * @return Protocol identifier field.
 */
uint8_t rmap_get_protocol(const uint8_t *header);

/** Set the protocol identifier for RMAP in a potential RMAP header.
 *
 * Set the protocol identifier to 1, which is the identifier for RMAP.
 *
 * @pre @p header must contain at least RMAP_HEADER_MINIMUM_SIZE bytes.
 *
 * @param[out] header Potential RMAP header.
 */
void rmap_set_protocol(uint8_t *header);

/** Get the instruction field from a potential RMAP header.
 *
 * @pre @p header must contain at least RMAP_HEADER_MINIMUM_SIZE bytes.
 *
 * @param[in] header Potential RMAP header.
 *
 * @return Instruction field.
 */
uint8_t rmap_get_instruction(const uint8_t *header);

/** Set the instruction field in a potential RMAP header.
 *
 * @pre @p header must contain at least RMAP_HEADER_MINIMUM_SIZE bytes.
 *
 * @param[out] header Potential RMAP header.
 * @param instruction Instruction field to copy into @p header.
 */
void rmap_set_instruction(uint8_t *header, uint8_t instruction);

/** Initialize a reply header for given command header.
 *
 * Initialize a reply header object with all members set to match a reply to a
 * successfully executed command.
 *
 * The status should be updated to match the actual result of the command execution.
 *
 * In case of a read command, the data length should be updated to match the
 * actual amount of data read.
 *
 * The RMAP command header object in @p command may be an invalid RMAP header
 * for which an error reply should be sent.
 *
 * @pre The RMAP command header object in @p command must be the result of a
 *      call to rmap_header_deserialize() which provided a deserialized header
 *      with the type RMAP_TYPE_COMMAND.
 *
 * @param[out] reply RMAP reply header object.
 * @param[in] command RMAP command header object.
 *
 * @retval RMAP_NO_REPLY No reply should be sent for this command based on the
 *         command codes.
 * @retval RMAP_OK Success, the reply has been initialized in @p reply.
 */
rmap_status_t rmap_header_initialize_reply(
    rmap_send_header_t *reply,
    const rmap_receive_command_header_t *command);

/** Calculate the size of a header if serialized.
 *
 * @param[out] serialized_size Size of the header if serialized.
 * @param[in] header RMAP header object.
 *
 * @retval RMAP_REPLY_ADDRESS_TOO_LONG The reply address length is greater than
 *         12.
 * @retval RMAP_UNUSED_PACKET_TYPE The value of @p header->type is invalid.
 * @retval RMAP_OK Success, the calculated serialized size is returned in @p
 *         serialized_size.
 */
rmap_status_t rmap_header_calculate_serialized_size(
    size_t *serialized_size,
    const rmap_send_header_t *header);

/** Serialize an RMAP header.
 *
 * If an unused combination of command codes for the given packet type is
 * given, the header will still be serialized. This is done in order to allow
 * serializing replies with an "unused packet type or command code" error from
 * a command with contained an unused command code, where the reply must
 * contain the same unused command code as the command.
 *
 * @pre If the target_address.length member of the header object is nonzero,
 *      the target_address.data member of the header object must be non-NULL.
 *
 * @param[out] serialized_size Size of the serialized header.
 * @param[out] data Destination for the serialized header.
 * @param data_size Maximum size available in @p data for the serialized
 *            header.
 * @param[in] header RMAP header object.
 *
 * @retval RMAP_NOT_ENOUGH_SPACE The serialized header would be larger than @p
 *         data_size.
 * @retval RMAP_REPLY_ADDRESS_TOO_LONG The reply address length is greater than
 *         12.
 * @retval RMAP_DATA_LENGTH_TOO_BIG The value of the data_length member of the
 *         header object is greater than the maximum possible RMAP data length
 *         (16777215).
 * @retval RMAP_UNUSED_PACKET_TYPE The value of @p header->type is invalid.
 * @retval RMAP_UNREPRESENTABLE_COMMAND_CODE The value given for command codes
 *         cannot be represented as an RMAP command code.
 * @retval RMAP_NO_REPLY @p header->type indicates that this is a reply, but
 *         the reply flag is not set in the command codes.
 * @retval RMAP_UNUSED_COMMAND_CODE The given command codes are an unused
 *         combination for the given packet type. The header has been
 *         serialized in @p data.
 * @retval RMAP_OK Success, the header has been serialized in @p data.
 */
rmap_status_t rmap_header_serialize(
    size_t *serialized_size,
    unsigned char *data,
    size_t data_size,
    const rmap_send_header_t *header);

/** Serialize an RMAP packet around an existing payload.
 *
 * Serialize an RMAP header before, and an RMAP data CRC after, an existing
 * payload.
 *
 * RMAP read commands and write replies are not valid input to this function,
 * since they do not contain a payload.
 *
 * If an unused combination of command codes for the given packet type is
 * given, the header will still be serialized. This is done in order to allow
 * serializing read replies with an "unused packet type or command code" error
 * from a read command with contained an unused command code, where the reply
 * must contain the same unused command code as the command.
 *
 * @pre If the target_address.length member of the header object is nonzero,
 *      the target_address.data member of the header object must be non-NULL.
 *
 * @param[out] serialized_offset Offset of the serialized header in @p data.
 * @param[out] serialized_size Size of the serialized header.
 * @param[out] data Destination for the serialized header.
 * @param data_size Maximum size available in @p data for the serialized
 *        header, the payload, and the RMAP CRC.
 * @param payload_offset Offset of the payload in @p data.
 * @param payload_size Size of the payload in @p data.
 * @param[in] header RMAP header object.
 *
 * @retval RMAP_ECSS_TOO_MUCH_DATA The packet type and command codes indicated
 *         that this was a read command or a write reply.
 * @retval RMAP_NOT_ENOUGH_SPACE The serialized header would not fit before the
 *         payload offset or there is no space after the payload end for the
 *         RMAP CRC.
 * @retval RMAP_REPLY_ADDRESS_TOO_LONG The reply address length is greater than
 *         12.
 * @retval RMAP_DATA_LENGTH_TOO_BIG The value of the data_length member of the
 *         header object is greater than the maximum possible RMAP data length
 *         (16777215).
 * @retval RMAP_UNUSED_PACKET_TYPE The value of @p header->type is invalid.
 * @retval RMAP_UNREPRESENTABLE_COMMAND_CODE The value given for command codes
 *         cannot be represented as an RMAP command code.
 * @retval RMAP_UNUSED_COMMAND_CODE The given command codes are an unused
 *         combination for the given packet type. The header has been
 *         serialized in @p data.
 * @retval RMAP_OK Success, the header has been serialized before the payload
 *         offset and the RMAP CRC has been appended after the payload end.
 */
rmap_status_t rmap_packet_serialize_inplace(
    size_t *serialized_offset,
    size_t *serialized_size,
    unsigned char *data,
    size_t data_size,
    size_t payload_offset,
    size_t payload_size,
    const rmap_send_header_t *header);

/** Deserialize the header from a received RMAP packet.
 *
 * The data length and data CRC is verified for write command packets only if
 * the verify-before-write bit is set in the received packet, otherwise this
 * verification must be handled by the caller.
 *
 * The absence of data is verified for read command and write reply packets.
 *
 * The data length and data CRC is verified for read reply packets.
 *
 * Some return values indicate an error in the header but also indicate that a
 * deserialized header is provided. This means that the @p header and
 * @p serialized_size parameters have been updated to represent the invalid
 * header. In the case of commands, a reply shall be sent based on this invalid
 * header if the command codes has the reply bit set, according to the RMAP
 * standard.
 *
 * Some return values indicate an error in the header but does not indicate
 * that a deserialized header is provided, in this case the @p header and
 * @p serialized_size parameters have not been updated, A reply shall not
 * be sent in these cases according to the RMAP standard.
 *
 * As a special case, the unused packet type error (indicated by the
 * RMAP_UNUSED_PACKET_TYPE return value) does not require a reply according to
 * the RMAP standard, however "the target may send a reply". A deserialized
 * header is provided in this case to allow sending a reply if desired.
 *
 * @param[out] serialized_size Size of the serialized header.
 * @param[in] header Destination for the deserialized header.
 * @param[in] data Start of the RMAP packet.
 * @param data_size Size of the RMAP packet in @p data.
 *
 * @retval RMAP_INCOMPLETE_HEADER @p data_size is not large enough to contain
 *         the RMAP header. No deserialized header is provided.
 * @retval RMAP_INCOMPLETE_PACKET @p data_size is not large enough to contain
 *         the whole packet based on the packet data length. No deserialized
 *         header is provided.
 * @retval RMAP_NO_RMAP_PROTOCOL The protocol identifier is not the identifier
 *         for the RMAP protocol. No deserialized header is provided.
 * @retval RMAP_HEADER_CRC_ERROR The header CRC is invalid. No deserialized
 *         header is provided.
 * @retval RMAP_ECSS_INVALID_DATA_CRC The data CRC is invalid (if
 *         applicable/verified). A deserialized header is provided.
 * @retval RMAP_UNUSED_PACKET_TYPE The packet type is invalid. A deserialized
 *         header is provided.
 * @Retval RMAP_UNUSED_COMMAND_CODE The command code combination is invalid for
 *         the packet type. A deserialized header is provided.
 * @retval RMAP_ECSS_TOO_MUCH_DATA The @p data_size indicates a packet size
 *         which is too large based on the packet type and data length (if
 *         applicable/verified). A deserialized header is provided.
 * @retval RMAP_OK No errors detected in header. A deserialized header is
 *         provided.
 */
rmap_status_t rmap_header_deserialize(
    size_t *serialized_size,
    rmap_receive_header_t *header,
    const unsigned char *data,
    size_t data_size);

/** Get string representation of an RMAP status or error constant.
 *
 * @param status RMAP status or error constant.
 *
 * @return RMAP status or error string.
 */
const char *rmap_status_text(rmap_status_t status);

/** Calculate RMAP CRC.
 *
 * @param[in] data Start of data to CRC.
 * @param data_size Size of data to CRC.
 *
 * @return CRC of data.
 */
uint8_t rmap_crc_calculate(const unsigned char *data, size_t data_size);

#endif /* RMAP_H */
