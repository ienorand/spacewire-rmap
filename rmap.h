#ifndef RMAP_H
#define RMAP_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

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
  RMAP_OK,
  RMAP_NULLPTR,
  RMAP_NOT_ENOUGH_SPACE,
  RMAP_REPLY_ADDRESS_TOO_LONG,
  RMAP_NO_RMAP_PROTOCOL,
  RMAP_HEADER_CRC_ERROR,
  RMAP_ECSS_INCOMPLETE_HEADER,
  RMAP_ECSS_ERROR_END_OF_PACKET,
  RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE,
  RMAP_ECSS_TOO_MUCH_DATA
} rmap_status_t;

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
    const uint8_t *data;
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
    const uint8_t *data;
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
    const uint8_t *data;
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
    const uint8_t *data;
    size_t length;
  } reply_address;
  uint8_t initiator_logical_address;
  unsigned char command_codes;
  uint8_t status;
  uint8_t target_logical_address;
  uint16_t transaction_identifier;
  uint32_t data_length;
} rmap_send_read_reply_header_t;

/** Representation of an RMAP write reply header after reception and
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

/** Calculate the size of a header if serialized.
 *
 * @param[out] serialized_size Size of the header if serialized.
 * @param[in] header RMAP header object.
 *
 * @retval RMAP_NULLPTR @p serialized_size, @p header or the reply_address
 *         member of the reply header object is NULL with a non-zero length
 *         set.
 * @retval RMAP_REPLY_ADDRESS_TOO_LONG The reply address length is greater than
 *         12.
 * @retval RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE The value of @p
 *         header->type is invalid.
 * @retval RMAP_OK Success, the calculated serialized size is returned in @p
 *         serialized_size.
 */
rmap_status_t rmap_header_calculate_serialized_size(
    size_t *serialized_size,
    const rmap_send_header_t *header);

/** Serialize an RMAP header.
 *
 * @param[out] serialized_size Size of the serialized header.
 * @param[in] data Destination for the serialized header.
 * @param data_size Maximum size available in @p data for the serialized
 *            header.
 * @param[in] header RMAP header object.
 *
 * @retval RMAP_NULLPTR @p serialized_size, @p data or @p header is NULL, or
 *         the target_address or reply_address member of the header object is
 *         NULL with a non-zero length set.
 * @retval RMAP_NOT_ENOUGH_SPACE The serialized header would be larger than @p
 *         data_size.
 * @retval RMAP_REPLY_ADDRESS_TOO_LONG The reply address length is greater than
 *         12.
 * @retval RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE The value of @p
 *         header->type is invalid or the command codes either contain an
 *         invalid value or an invalid combination for the given packet type.
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
 * @param[out] serialized_offset Offset of the serialized header in @p data.
 * @param[out] serialized_size Size of the serialized header.
 * @param[in] data Destination for the serialized header.
 * @param data_size Maximum size available in @p data for the serialized
 *        header, the payload, and the RMAP CRC.
 * @param[in] payload_offset Offset of the payload in @p data.
 * @param[in] payload_size Size of the payload in @p data.
 * @param[in] header RMAP header object.
 *
 * @retval RMAP_NULLPTR @p serialized_size, @p serialized_offset, @p data or @p
 *         header is NULL, or the target_address or reply_address member of the
 *         header object is NULL with a non-zero length set.
 * @retval RMAP_ECSS_TOO_MUCH_DATA The packet type and command codes indicated
 *         that this was a read command or a write reply.
 * @retval RMAP_NOT_ENOUGH_SPACE The serialized header would not fit before the
 *         payload offset or there is no space after the payload end for the
 *         RMAP CRC.
 * @retval RMAP_REPLY_ADDRESS_TOO_LONG The reply address length is greater than
 *         12.
 * @retval RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE The value of @p
 *         header->type is invalid or the command codes either contain an
 *         invalid value or an invalid combination for the given packet type.
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

/** Deserialize an RMAP header.
 *
 * @param[out] serialized_size Size of the serialized header.
 * @param[in] header Destination for the deserialized header.
 * @param[in] data Location of the serialized header.
 * @param data_size Size available in @p data for the serialized header.
 *
 * @retval RMAP_NULLPTR @p serialized_size, @p header or @p data is NULL.
 * @retval RMAP_ECSS_INCOMPLETE_HEADER @p data_size is not large enough to
 *         contain the RMAP header.
 * @retval RMAP_NO_RMAP_PROTOCOL The protocol identifier is not the identifier
 *         for the RMAP protocol.
 * @retval RMAP_ECSS_UNUSED_PACKET_TYPE_OR_COMMAND_CODE The packet type is
 *         invalid or the command code combination is invalid for the packet
 *         type.
 * @retval RMAP_HEADER_CRC_ERROR The header CRC is invalid.
 * @retval RMAP_OK Success, the header has been deserialized in @p header and
 *         its serialized size is given in @p serialized_size.
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

/** Calculate RMAP crc.
 *
 * @param[in] data Start of data to CRC.
 * @param data_size Size of data to CRC.
 *
 * @return CRC of data.
 */
uint8_t rmap_crc_calculate(const unsigned char *data, size_t data_size);

/* TODO: Implement or remove. */
void rmap_data_crc_put(unsigned char *data, size_t data_size);

#endif /* RMAP_H */
