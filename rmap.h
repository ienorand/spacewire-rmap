#ifndef RMAP_H
#define RMAP_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

/** Deserialized representation of RMAP header type. */
typedef enum {
  RMAP_TYPE_COMMAND,
  RMAP_TYPE_WRITE_REPLY,
  RMAP_TYPE_READ_REPLY
} rmap_type_t;

/** Deserialized representation of RMAP command codes. */
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

  RMAP_ECSS_INCOMPLETE_HEADER,
  RMAP_ECSS_ERROR_END_OF_PACKET,
  RMAP_ECSS_HEADER_CRC_ERROR,
  RMAP_ECSS_UNUSED_PACKET_TYPE,
  RMAP_ECSS_INVALID_COMMAND_CODE,
  RMAP_ECSS_TOO_MUCH_DATA
} rmap_status_t;

/** Common deserialized representation of RMAP write and read command headers.
 */
typedef struct {
  /** Target address, empty after deserialization. */
  struct {
    uint8_t *data;
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
} rmap_command_header_t;

/** Deserialized representation of RMAP write reply header. */
typedef struct {
  /** Reply address, empty after deserialization. */
  struct {
    uint8_t *data;
    size_t length;
  } reply_address;
  uint8_t initiator_logical_address;
  unsigned char command_codes;
  uint8_t status;
  uint8_t target_logical_address;
  uint16_t transaction_identifier;
} rmap_write_reply_header_t;

/** Deserialized representation of RMAP read reply header. */
typedef struct {
  /** Reply address, empty after deserialization. */
  struct {
    uint8_t *data;
    size_t length;
  } reply_address;
  uint8_t initiator_logical_address;
  unsigned char command_codes;
  uint8_t status;
  uint8_t target_logical_address;
  uint16_t transaction_identifier;
  uint32_t data_length;
} rmap_read_reply_header_t;

/** Tagged union representation of all deserialized RMAP headers. */
typedef struct {
  /** Tag indicating the valid RMAP header type. */
  rmap_type_t type;
  union {
    rmap_command_header_t command;
    rmap_write_reply_header_t write_reply;
    rmap_read_reply_header_t read_reply;
  } t;
} rmap_header_t;

/** Calculate the size of a header if serialized.
 *
 * @param[out] size Header size if serialized.
 * @param[in] header RMAP header object.
 *
 * @retval RMAP_NULLPTR @p serialized_size, @p header or the reply_address
 *         member of the reply header object was NULL.
 * @retval RMAP_REPLY_ADDRESS_TOO_LONG The reply address length was greater
 *         than 12.
 * @retval RMAP_ECSS_UNUSED_PACKET_TYPE The value of @p header->type was
 *         invalid.
 * @ertval RMAP_OK Success, the calculated serialized size is returned in @p
 *         serialized_size.
 */
rmap_status_t rmap_header_calculate_serialized_size(
    size_t *serialized_size,
    const rmap_header_t *header);

rmap_status_t rmap_header_serialize(
    size_t *serialized_size,
    unsigned char *data,
    size_t data_size,
    const rmap_header_t *header);

rmap_status_t rmap_header_deserialize(
    size_t *serialized_size,
    rmap_header_t *header,
    unsigned char *data,
    size_t data_size);

char *rmap_status_text(rmap_status_t status);

uint8_t rmap_crc_calculate(const unsigned char *data, size_t data_size);
void rmap_data_crc_put(unsigned char *data, size_t data_size);

#endif /* RMAP_H */
