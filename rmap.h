#ifndef RMAP_H
#define RMAP_H

/** Serializing and deserializing for SpaceWire RMAP.
 *
 * @file
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Bit offset of packet type in instruction field. */
#define RMAP_INSTRUCTION_PACKET_TYPE_SHIFT 6
/** Bit mask of packet type in instruction field. */
#define RMAP_INSTRUCTION_PACKET_TYPE_MASK \
    (0x3 << RMAP_INSTRUCTION_PACKET_TYPE_SHIFT)

/** Bit offset of command code in instruction field. */
#define RMAP_INSTRUCTION_COMMAND_CODE_SHIFT 2
/** Bit mask of command code in instruction field. */
#define RMAP_INSTRUCTION_COMMAND_CODE_MASK \
    (0xF << RMAP_INSTRUCTION_COMMAND_CODE_SHIFT)

/** Bit offset of reply address length in instruction field. */
#define RMAP_INSTRUCTION_REPLY_ADDRESS_LENGTH_SHIFT 0
/** Bit mask of reply address length in instruction field. */
#define RMAP_INSTRUCTION_REPLY_ADDRESS_LENGTH_MASK \
    (0x3 << RMAP_INSTRUCTION_REPLY_ADDRESS_LENGTH_SHIFT)

/** Representation of RMAP packet type. */
enum rmap_packet_type {
    RMAP_PACKET_TYPE_REPLY = 0x0,
    RMAP_PACKET_TYPE_COMMAND = 0x1,
    RMAP_PACKET_TYPE_REPLY_RESERVED = 0x2,
    RMAP_PACKET_TYPE_COMMAND_RESERVED = 0x3
};

/** Representation of RMAP command codes. */
enum {
    RMAP_COMMAND_CODE_WRITE = 1 << 3,
    RMAP_COMMAND_CODE_VERIFY = 1 << 2,
    RMAP_COMMAND_CODE_REPLY = 1 << 1,
    RMAP_COMMAND_CODE_INCREMENT = 1 << 0,
    RMAP_COMMAND_CODE_RMW = RMAP_COMMAND_CODE_VERIFY | RMAP_COMMAND_CODE_REPLY |
        RMAP_COMMAND_CODE_INCREMENT,
};

/** Standardised RMAP status and error codes.
 *
 * Standardized error and status codes which can be used in the status field of
 * RMAP write or read replies.
 */
enum rmap_status_field_code {
    /** Standardized RMAP status field code for "command executed successfully".
     */
    RMAP_STATUS_FIELD_CODE_SUCCESS = 0,

    /** Standardized RMAP status field code for "general error code".
     *
     * Error description according to the RMAP standard:
     *
     * > The detected error does not fit into the other error cases or the node
     * > does not support further distinction between the errors.
     */
    RMAP_STATUS_FIELD_CODE_GENERAL_ERROR_CODE = 1,

    /** Standardized RMAP status field code for "unused RMAP packet type or
     *  command code".
     *
     * Error description according to the RMAP standard:
     *
     * > The Header CRC was decoded correctly but the packet type is reserved or
     * > the command is not used by the RMAP protocol.
     */
    RMAP_STATUS_FIELD_CODE_UNUSED_PACKET_TYPE_OR_COMMAND_CODE = 2,

    /** Standardized RMAP status field code for "invalid key".
     *
     * Error description according to the RMAP standard:
     *
     * > The Header CRC was decoded correctly but the device key did not match
     * > that expected by the target user application.
     */
    RMAP_STATUS_FIELD_CODE_INVALID_KEY = 3,

    /** Standardized RMAP status field code for "invalid data CRC".
     *
     * Error description according to the RMAP standard:
     *
     * > Error in the CRC of the data field.
     */
    RMAP_STATUS_FIELD_CODE_INVALID_DATA_CRC = 4,

    /** Standardized RMAP status field code for "early EOP".
     *
     * Error description according to the RMAP standard:
     *
     * > EOP marker detected before the end of the data.
     *
     * This error can also be reported as error information to the target node
     * according to the RMAP standard.
     */
    RMAP_STATUS_FIELD_CODE_EARLY_EOP = 5,

    /** Standardized RMAP status field code for "too much data".
     *
     * Error description according to the RMAP standard:
     *
     * > More than the expected amount of data in a command has been received.
     */
    RMAP_STATUS_FIELD_CODE_TOO_MUCH_DATA = 6,

    /** Standardized RMAP status field code for "EEP".
     *
     * Error description according to the RMAP standard:
     *
     * > EEP marker detected immediately after the header CRC or during the
     * > transfer of data and Data CRC or immediately thereafter. Indicates that
     * > there was a communication failure of some sort on the network.
     *
     * This error can also be reported as error information to the target node
     * according to the RMAP standard.
     */
    RMAP_STATUS_FIELD_CODE_EEP = 7,

    /** Standardized RMAP status field code for "verify buffer overrun".
     *
     * Error description according to the RMAP standard:
     *
     * > The verify before write bit of the command was set so that the data
     * > field was buffered in order to verify the Data CRC before transferring
     * > the data to target memory. The data field was longer than able to fit
     * > inside the verify buffer resulting in a buffer overrun.
     * >
     * > Note that the command is not executed in this case.
     */
    RMAP_STATUS_FIELD_CODE_VERIFY_BUFFER_OVERRUN = 9,

    /** Standardized RMAP status field code for "RMAP command not implemented or
     *  not authorised".
     *
     * Error description according to the RMAP standard:
     *
     * > The target user application did not authorise the requested operation.
     * > This may be because the command requested has not been implemented.
     */
    RMAP_STATUS_FIELD_CODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED = 10,

    /** Standardized RMAP status field code for "RMW data length error".
     *
     * Error description according to the RMAP standard:
     *
     * > The amount of data in a RMW command is invalid (0x01, 0x03, 0x05, 0x07
     * > or greater than 0x08).
     */
    RMAP_STATUS_FIELD_CODE_RMW_DATA_LENGTH_ERROR = 11,

    /** Standardized RMAP status field code for "invalid target logical
     * address".
     *
     * Error description according to the RMAP standard:
     *
     * > The Header CRC was decoded correctly but the Target Logical Address was
     * > not the value expected by the target.
     */
    RMAP_STATUS_FIELD_CODE_INVALID_TARGET_LOGICAL_ADDRESS = 12
};

/** Non-standard library-specific status constants.
 *
 * Some of these constants overlap in their meaning with one or both of:
 * - Standardized RMAP status field error and status codes.
 * - Standardized RMAP error information.
 *
 * All of these status constants, except for RMAP_OK, use numeric values
 * starting from 255 + 1 in order to avoid numeric overlap with standardized
 * RMAP status field error and status codes.
 */
enum rmap_status {
    /** Success. */
    RMAP_OK = 0,

    /** The provided data is not large enough to contain the full RMAP header.
     */
    RMAP_INCOMPLETE_HEADER = 256,

    /** The protocol field indicates that this is not an RMAP packet. */
    RMAP_NO_RMAP_PROTOCOL = 257,

    /** The header CRC indicates that errors are present in the header. */
    RMAP_HEADER_CRC_ERROR = 258,

    /** The packet type field has the reserved bit set. */
    RMAP_UNUSED_PACKET_TYPE = 259,

    /** The command field contains a reserved command code. */
    RMAP_UNUSED_COMMAND_CODE = 260,

    /** A reply packet type was combined with a without-reply command code. */
    RMAP_NO_REPLY = 261,

    /** The provided packet does not contain a data field based on its header.
     */
    RMAP_NO_DATA = 262,

    /** There is less data in the data field than indicated in the header data
     *  length field.
     */
    RMAP_INSUFFICIENT_DATA = 263,

    /** There is more data than expected from the packet type and/or data field
     *  length.
     */
    RMAP_TOO_MUCH_DATA = 264,

    /** The data CRC indicates that errors are present in the data. */
    RMAP_INVALID_DATA_CRC = 265,

    /** The data length field of a RMW command or RMW reply has an invalid
     *  value.
     */
    RMAP_RMW_DATA_LENGTH_ERROR = 266,

    /** The provided packet type value cannot be represented in an RMAP header
     *  packet type field.
     *
     * This error indicates that an attempt was made to initialize/serialize a
     * header with a packet type value that is not one of:
     * - RMAP_PACKET_TYPE_COMMAND.
     * - RMAP_PACKET_TYPE_REPLY.
     * - RMAP_PACKET_TYPE_COMMAND_RESERVED.
     * - RMAP_PACKET_TYPE_REPLY_RESERVED.
     */
    RMAP_INVALID_PACKET_TYPE = 267,

    /** The provided command code value cannot be represented in an RMAP header
     *  command field.
     *
     * This error indicates that an attempt was made to initialize/serialize a
     * header with a command code value that is less than 0 or greater than the
     * combination of all available command code flags (0xF).
     */
    RMAP_INVALID_COMMAND_CODE = 268,

    /** The provided reply address is longer than 12 bytes. */
    RMAP_REPLY_ADDRESS_TOO_LONG = 269,

    /** Not enough space to initialize header. */
    RMAP_NOT_ENOUGH_SPACE = 270
};

/** Size constants for RMAP packets. */
enum {
    RMAP_COMMAND_HEADER_STATIC_SIZE = 16,
    RMAP_WRITE_REPLY_HEADER_STATIC_SIZE = 8,
    RMAP_READ_REPLY_HEADER_STATIC_SIZE = 12,
    RMAP_HEADER_MINIMUM_SIZE = RMAP_WRITE_REPLY_HEADER_STATIC_SIZE,

    RMAP_REPLY_ADDRESS_LENGTH_MAX = 12,
    RMAP_HEADER_SIZE_MAX =
        RMAP_COMMAND_HEADER_STATIC_SIZE + RMAP_REPLY_ADDRESS_LENGTH_MAX,
};

/** Maximum value in RMAP data length field and maximum size of RMAP data
 *  field.
 */
#define RMAP_DATA_LENGTH_MAX ((INT32_C(1) << 24) - 1)

/** Maximum size of an RMAP packet excluding target address or reply address
 *  prefix.
 */
#define RMAP_PACKET_SIZE_MAX (RMAP_HEADER_SIZE_MAX + RMAP_DATA_LENGTH_MAX + 1)

/** Get the protocol identifier field from a potential RMAP header.
 *
 * @pre @p header must contain at least RMAP_HEADER_MINIMUM_SIZE bytes.
 *
 * @param[in] header Potential RMAP header.
 *
 * @return Protocol identifier field.
 */
uint8_t rmap_get_protocol(const void *header);

/** Set the protocol identifier for RMAP in a potential RMAP header.
 *
 * Set the protocol identifier to 1, which is the identifier for RMAP.
 *
 * @pre @p header must contain at least RMAP_HEADER_MINIMUM_SIZE bytes.
 *
 * @param[out] header Potential RMAP header.
 */
void rmap_set_protocol(void *header);

/** Get the instruction field from a potential RMAP header.
 *
 * @pre @p header must contain at least RMAP_HEADER_MINIMUM_SIZE bytes.
 *
 * @param[in] header Potential RMAP header.
 *
 * @return Instruction field.
 */
uint8_t rmap_get_instruction(const void *header);

/** Set the instruction field in a potential RMAP header.
 *
 * @pre @p header must contain at least RMAP_HEADER_MINIMUM_SIZE bytes.
 *
 * @param[out] header Potential RMAP header.
 * @param instruction Instruction field to copy into @p header.
 */
void rmap_set_instruction(void *header, uint8_t instruction);

/** Determine if the packet type is "command" in an instruction field.
 *
 * The reserved bit in the packet type field is ignored and unused packet types
 * are reported as commands or replies based only on the command/reply bit.
 *
 * @param instruction Instruction field.
 *
 * @retval true Packet type is "command".
 * @retval false Packet type is "reply".
 */
bool rmap_is_instruction_command(uint8_t instruction);

/** Determine if the packet type is "command" in a potential RMAP header.
 *
 * The reserved bit in the packet type field is ignored and unused packet types
 * are reported as commands or replies based only on the command/reply bit.
 *
 * @pre @p header must contain at least RMAP_HEADER_MINIMUM_SIZE bytes.
 *
 * @param[in] header Potential RMAP header.
 *
 * @retval true Packet type is "command".
 * @retval false Packet type is "reply".
 */
bool rmap_is_command(const void *header);

/** Determine if the packet type is "unused" in an instruction field.
 *
 * Determine if the packet type field indicates a reserved packet type.
 *
 * @param instruction Instruction field.
 *
 * @retval true Packet type is "unused".
 * @retval false Packet type is "command" or "reply".
 */
bool rmap_is_instruction_unused_packet_type(uint8_t instruction);

/** Determine if the packet type is "unused" in a potential RMAP header.
 *
 * Determine if the packet type field indicates a reserved packet type.
 *
 * @pre @p header must contain at least RMAP_HEADER_MINIMUM_SIZE bytes.
 *
 * @param[in] header Potential RMAP header.
 *
 * @retval true Packet type is "unused".
 * @retval false Packet type is "command" or "reply".
 */
bool rmap_is_unused_packet_type(const void *header);

/** Determine if the command type is "write" in an instruction field.
 *
 * @param instruction Instruction field.
 *
 * @retval true Command type is "write".
 * @retval false Command type is "read".
 */
bool rmap_is_instruction_write(uint8_t instruction);

/** Determine if the command type is "write" in a potential RMAP header.
 *
 * @pre @p header must contain at least RMAP_HEADER_MINIMUM_SIZE bytes.
 *
 * @param[in] header Potential RMAP header.
 *
 * @retval true Command type is "write".
 * @retval false Command type is "read".
 */
bool rmap_is_write(const void *header);

/** Determine if the command type is "verified" in an instruction field.
 *
 * Determine if the command type indicates that data shall be verified before
 * writing (or have been verified before writing if this is a reply).
 *
 * @param instruction Instruction field.
 *
 * @retval true Command type is "verified".
 * @retval false Command type is "non-verified".
 */
bool rmap_is_instruction_verify_data_before_write(uint8_t instruction);

/** Determine if the command type is "verified" in a potential RMAP header.
 *
 * Determine if the command type indicates that data shall be verified before
 * writing (or have been verified before writing if this is a reply).
 *
 * @pre @p header must contain at least RMAP_HEADER_MINIMUM_SIZE bytes.
 *
 * @param[in] header Potential RMAP header.
 *
 * @retval true Command type is "verified".
 * @retval false Command type is "non-verified".
 */
bool rmap_is_verify_data_before_write(const void *header);

/** Determine if the command type is "with-reply" in an instruction field.
 *
 * Determine if the command type indicates that the command shall be
 * acknowledged with a reply after completion (or have been acknowledged with a
 * reply if this is the reply).
 *
 * @param instruction Instruction field.
 *
 * @retval true Command type is "with-reply".
 * @retval false Command type is "without-reply".
 */
bool rmap_is_instruction_with_reply(uint8_t instruction);

/** Determine if the command type is "with-reply" in a potential RMAP header.
 *
 * Determine if the command type indicates that the command shall be
 * acknowledged with a reply after completion (or have been acknowledged with a
 * reply if this is the reply).
 *
 * @pre @p header must contain at least RMAP_HEADER_MINIMUM_SIZE bytes.
 *
 * @param[in] header Potential RMAP header.
 *
 * @retval true Command type is "with-reply".
 * @retval false Command type is "without-reply".
 */
bool rmap_is_with_reply(const void *header);

/** Determine if the command type is "incrementing" in an instruction field.
 *
 * Determine if the command type indicates that the operation (read or write)
 * shall be done with sequential memory addresses (as opposed to with a single
 * memory address) (or have been done with sequential memory addresses if this
 * is a reply).
 *
 * @param instruction Instruction field.
 *
 * @retval true Command type is "incrementing".
 * @retval false Command type is "single-address".
 */
bool rmap_is_instruction_increment_address(uint8_t instruction);

/** Determine if the command type is "incrementing" in a potential RMAP header.
 *
 * Determine if the command type indicates that the operation (read or write)
 * shall be done with sequential memory addresses (as opposed to with a single
 * memory address) (or have been done with sequential memory addresses if this
 * is a reply).
 *
 * @pre @p header must contain at least RMAP_HEADER_MINIMUM_SIZE bytes.
 *
 * @param[in] header Potential RMAP header.
 *
 * @retval true Command type is "incrementing".
 * @retval false Command type is "single-address".
 */
bool rmap_is_increment_address(const void *header);

/** Determine if the command code is "RMW" in an instruction field.
 *
 * Determine if the command code indicates that the command type is
 * Read-Modify-Write.
 *
 * @param instruction Instruction field.
 *
 * @retval true Command code represent an "RMW" command type.
 * @retval false Command code does not represent an "RMW" command type.
 */
bool rmap_is_instruction_rmw(uint8_t instruction);

/** Determine if the command code is "RMW" in a potential RMAP header.
 *
 * Determine if the command code indicates that the command type is
 * Read-Modify-Write.
 *
 * @pre @p header must contain at least RMAP_HEADER_MINIMUM_SIZE bytes.
 *
 * @param[in] header Potential RMAP header.
 *
 * @retval true Command code represents an "unused" command type.
 * @retval false Command code represents a valid command type.
 */
bool rmap_is_rmw(const void *header);

/** Determine if the command code is "unused" in an instruction field.
 *
 * Determine if the command code represents an invalid command type which is
 * not used by the RMAP protocol.
 *
 * @param instruction Instruction field.
 *
 * @retval true Command code represents an "unused" command type.
 * @retval false Command code represents a valid command type.
 */
bool rmap_is_instruction_unused_command_code(uint8_t instruction);

/** Determine if the command code is "unused" in a potential RMAP header.
 *
 * Determine if the command code represents an invalid command type which is
 * not used by the RMAP protocol.
 *
 * @pre @p header must contain at least RMAP_HEADER_MINIMUM_SIZE bytes.
 *
 * @param[in] header Potential RMAP header.
 *
 * @retval true Command code represents an "unused" command type.
 * @retval false Command code represents a valid command type.
 */
bool rmap_is_unused_command_code(const void *header);

/** Get the key field from a verified RMAP command header.
 *
 * @pre @p header must contain a verified RMAP command header.
 *
 * @param[in] header Verified RMAP command header.
 *
 * @return Key field.
 */
uint8_t rmap_get_key(const void *header);

/** Set the key field in a potential RMAP command header.
 *
 * @pre @p header must contain at least RMAP_HEADER_MINIMUM_SIZE bytes.
 *
 * @param[out] header Potential RMAP header.
 * @param key Key field to copy into @p header.
 */
void rmap_set_key(void *header, uint8_t key);

/** Get the status field from verified RMAP reply header.
 *
 * @pre @p header must contain a verified RMAP reply header.
 *
 * @param[in] header Verified RMAP reply header.
 *
 * @return Status field.
 */
uint8_t rmap_get_status(const void *header);

/** Set the status field in a potential RMAP reply header.
 *
 * @pre @p header must contain at least RMAP_HEADER_MINIMUM_SIZE bytes.
 *
 * @param[out] header Potential RMAP header.
 * @param status Status field to copy into @p header.
 */
void rmap_set_status(void *header, uint8_t status);

/** Get the reply address data and length from a verified RMAP command header.
 *
 * Leading zero-padding in the reply address will be removed, resulting in an
 * address that is ready to use as a spacewire address.
 *
 * The initiator logical address is not included in the copied reply address.
 *
 * @pre @p header must contain a verified RMAP command header.
 *
 * @param[out] reply_address Destination for reply address.
 * @param[out] reply_address_size Number of bytes copied into @p reply_address
 *             on success.
 * @param reply_address_max_size Number of bytes available in
 *        @p reply_address.
 * @param[in] header Verified RMAP command header.
 *
 * @retval RMAP_NOT_ENOUGH_SPACE @p reply_address_max_size is less than the
 *         size of the reply address.
 * @retval RMAP_OK Reply address was successfully copied to @p reply_address
 *         and its size is given in @p reply_address_size.
 */
enum rmap_status rmap_get_reply_address(
    uint8_t *reply_address,
    size_t *reply_address_size,
    size_t reply_address_max_size,
    const void *header);

/** Set the reply address field in an initialized RMAP command header.
 *
 * @pre @p header must contain an initialized RMAP command header.
 * @pre @p reply_address_size must match the (padded) length set in the reply
 *      address length field in @p header.
 *
 * @param[out] header Initialized RMAP command header.
 * @param[in] reply_address Reply address field to copy into @p header.
 * @param reply_address_size Number of bytes to copy from @p reply_address.
 */
void rmap_set_reply_address(
    void *header,
    const uint8_t *reply_address,
    size_t reply_address_size);

/** Get the target logical address field from a potential RMAP header.
 *
 * @pre @p header must contain at least RMAP_HEADER_MINIMUM_SIZE bytes.
 * @pre @p header must have a correct packet type field.
 *
 * @param[in] header Potential RMAP header.
 *
 * @return Target logical address field.
 */
uint8_t rmap_get_target_logical_address(const void *header);

/** Set the target logical address field in a potential RMAP header.
 *
 * @pre @p header must contain at least RMAP_HEADER_MINIMUM_SIZE bytes.
 * @pre @p header must have a correct packet type field.
 *
 * @param[out] header Potential RMAP header.
 * @param target_logical_address Target logical address field to copy into
 *        @p header.
 */
void rmap_set_target_logical_address(
    void *header,
    uint8_t target_logical_address);

/** Get the initiator logical address field from a verified RMAP header.
 *
 * @pre @p header must contain a verified RMAP header.
 *
 * @param[in] header Verified RMAP header.
 *
 * @return Initiator logical address field.
 */
uint8_t rmap_get_initiator_logical_address(const void *header);

/** Set the initiator logical address field in an initialized RMAP header.
 *
 * @pre @p header must contain an initialized RMAP header.
 *
 * @param[out] header Initialized RMAP header.
 * @param initiator_logical_address Initiator logical address field to copy
 *        into @p header.
 */
void rmap_set_initiator_logical_address(
    void *header,
    uint8_t initiator_logical_address);

/** Get the transaction identifier field from a verified RMAP header.
 *
 * @pre @p header must contain a verified RMAP header.
 *
 * @param[in] header Verified RMAP header.
 *
 * @return Transaction identifier field.
 */
uint16_t rmap_get_transaction_identifier(const void *header);

/** Set the transaction identifier field in an initialized RMAP header.
 *
 * @pre @p header must contain an initialized RMAP header.
 *
 * @param[out] header Initialized RMAP header.
 * @param transaction_identifier Transaction identifier field to copy into
 *        @p header.
 */
void rmap_set_transaction_identifier(
    void *header,
    uint16_t transaction_identifier);

/** Set the reserved field in a potential RMAP read reply or RMW reply header.
 *
 * Set the reserved field to 0x00.
 *
 * @pre @p header must contain at least RMAP_READ_REPLY_HEADER_STATIC_SIZE
 *      bytes.
 *
 * @param[out] header Potential RMAP read reply or RMW reply header.
 */
void rmap_set_reserved(void *header);

/** Get the extended address field from a verified RMAP command header.
 *
 * @pre @p header must contain a verified RMAP command header.
 *
 * @param[in] header Verified RMAP command header.
 *
 * @return Extended address field.
 */
uint8_t rmap_get_extended_address(const void *header);

/** Set the extended address field in an initialized RMAP command header.
 *
 * @pre @p header must contain an initialized RMAP command header.
 *
 * @param[out] header Initialized RMAP command header.
 * @param extended_address Extended address field to copy into @p header.
 */
void rmap_set_extended_address(void *header, uint8_t extended_address);

/** Get the address field from a verified RMAP command header.
 *
 * @pre @p header must contain a verified RMAP command header.
 *
 * @param[in] header Verified RMAP command header.
 *
 * @return Address field.
 */
uint32_t rmap_get_address(const void *header);

/** Set the address field in an initialized RMAP command header.
 *
 * @pre @p header must contain an initialized RMAP command header.
 *
 * @param[out] header Initialized RMAP command header.
 * @param address Address field to copy into @p header.
 */
void rmap_set_address(void *header, uint32_t address);

/** Get the data length field from a verified RMAP command, read reply, or RMW
 *  reply header.
 *
 * The data length will be reported as 0 for RMAP write reply headers, since
 * they contain no data length field.
 *
 * @pre @p header must contain a verified RMAP header.
 *
 * @param[in] header Verified RMAP header.
 *
 * @return Data length field or 0 for write replies.
 */
uint32_t rmap_get_data_length(const void *header);

/** Set the data length field in an initialized RMAP command, read reply, or
 *  RMW reply header.
 *
 * Will do nothing if @p header contains an RMAP write reply, since they
 * contain no data length field.
 *
 * @pre @p data_length must be less than or equal to RMAP_DATA_LENGTH_MAX.
 *
 * @pre @p header must contain an initialized RMAP header.
 *
 * @param[out] header Initialized RMAP command, read reply, or RMW reply
 *             header.
 * @param data_length Data length field to copy into @p header.
 */
void rmap_set_data_length(void *header, uint32_t data_length);

/** Calculate and set the header CRC field in an initialized RMAP header.
 *
 * @pre @p header must contain an initialized RMAP header.
 *
 * @param[in] header Initialized RMAP header.
 */
void rmap_calculate_and_set_header_crc(void *header);

/** Calculate the RMAP header size from a potential RMAP header.
 *
 * @pre @p header must contain at least RMAP_HEADER_MINIMUM_SIZE bytes.
 * @pre @p header must have a valid packet type field.
 * @pre @p header must have a valid command field.
 *
 * @param header Potential RMAP header.
 *
 * @return RMAP header size.
 */
size_t rmap_calculate_header_size(const void *header);

/** Verify the integrity of a potential RMAP header.
 *
 * Verify that the data in @p header:
 * - Contains an RMAP header based on the protocol field.
 * - Is large enough to fit the whole RMAP header based on its type.
 * - Has a valid RMAP header CRC.
 *
 * No verification of the instruction field is performed.
 *
 * @p size May be larger than the size of the header being verified.
 *
 * @param[in] header Potential RMAP header.
 * @param size Number of bytes in @p header.
 *
 * @retval RMAP_INCOMPLETE_HEADER @p size is too small to fit the whole header.
 * @retval RMAP_NO_RMAP_PROTOCOL The protocol field indicates that this is not
 *         an RMAP header.
 * @retval RMAP_HEADER_CRC_ERROR The header CRC indicates that errors are
 *         present in the header.
 * @retval RMAP_OK Header is a complete RMAP header.
 */
enum rmap_status rmap_verify_header_integrity(const void *header, size_t size);

/** Verify the instruction field in a potential RMAP header.
 *
 * @pre The RMAP header in @p header must have been verified to be complete via
 *      rmap_verify_header_integrity().
 *
 * @param header Potential RMAP header.
 *
 * @retval RMAP_UNUSED_PACKET_TYPE The packet type field has the reserved bit
 *         set.
 * @retval RMAP_UNUSED_COMMAND_CODE The command field contains a reserved
 *         command code.
 * @retval RMAP_NO_REPLY The packet type field indicates that this is a reply
 *         but the command field do not have the reply bit set.
 * @retval RMAP_OK Instruction is valid.
 */
enum rmap_status rmap_verify_header_instruction(const void *header);

/** Verify the data field in a potential RMAP packet.
 *
 * @pre The RMAP header in @p packet must have been verified to be complete via
 *      rmap_verify_header_integrity().
 * @pre @p size Must be equal to the size of the packet being verified.
 *
 * @param[in] packet Potential RMAP packet.
 * @param size Number of bytes in @p packet.
 *
 * @retval RMAP_NO_DATA The packet is a type (read command or write reply)
 *         which do not contain a data field.
 * @retval RMAP_RMW_DATA_LENGTH_ERROR The packet is an RMW command or RMW reply
 *         and the data length field has an invalid value.
 * @retval RMAP_INSUFFICIENT_DATA @p size is too small to fit the whole packet.
 * @retval RMAP_TOO_MUCH_DATA @p size is larger than the packet based on the
 *         data length field.
 * @retval RMAP_INVALID_DATA_CRC The data CRC indicates that errors are present
 *         in the data field.
 * @retval RMAP_OK Data field is valid.
 */
enum rmap_status rmap_verify_data(const void *packet, size_t size);

/** Initialize an RMAP header.
 *
 * - Verify that the header would fit in @p max_size.
 * - Set the protocol identifier field to indicate an RMAP packet.
 * - Set the instruction field based on the provided parameters.
 *
 * The prefix spacewire address is not set.
 *
 * The instruction field fully defines the format of an RMAP packet, so all
 * further writes via accessor function will be valid if this initialization
 * succeeds.
 *
 * Creating invalid headers with unused packet types or unused command codes is
 * supported in order to allow creating invalid RMAP packets for testing
 * purposes.
 *
 * @param[out] header Destination for the header.
 * @param max_size Maximum number of bytes to write into @p header.
 * @param packet_type Packet type to set in instruction field.
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
 * @retval RMAP_NOT_ENOUGH_SPACE @p max_size is less than the size of the
 *         header.
 * @retval RMAP_OK RMAP header initialized successfully.
 */
enum rmap_status rmap_initialize_header(
    void *header,
    size_t max_size,
    enum rmap_packet_type packet_type,
    int command_code,
    size_t reply_address_unpadded_size);

/** Initialize an RMAP header before an existing data field.
 *
 * - Verify that the header would fit before the data field.
 * - Set the protocol identifier field to indicate an RMAP packet.
 * - Set the instruction field based on the provided parameters.
 *
 * The prefix spacewire address is not set.
 *
 * The instruction field fully defines the format of an RMAP packet, so all
 * further writes via accessor function will be valid if this initialization
 * succeeds
 *
 * @param[out] header_offset Offset of start of written header from @p raw.
 * @param[out] raw Start of area containing the existing data field and into
 *             which the header will be written.
 * @param data_offset Offset of existing data field from @p raw.
 * @param packet_type Packet type to set in instruction field.
 * @param command_code Representation of command code flags to set in
 *        instruction field.
 * @param reply_address_unpadded_size Reply address size without leading
 *        zero-padding used to calculate and set the reply address length
 *        field.
 *
 * @retval RMAP_UNUSED_PACKET_TYPE @p packet_type contains an unrepresentable
 *         packet type.
 * @retval RMAP_INVALID_COMMAND_CODE @p command_code contains an
 *         unrepresentable command code.
 * @retval RMAP_UNUSED_COMMAND_CODE @p command_code contains a reserved command
 *         code.
 * @retval RMAP_NO_REPLY @p packet_type is a reply but @p command_code does not
 *         contain a with-reply command code.
 * @retval RMAP_REPLY_ADDRESS_TOO_LONG @p reply_address_unpadded_size is larger
 *         than RMAP_REPLY_ADDRESS_LENGTH_MAX.
 * @retval RMAP_NOT_ENOUGH_SPACE Header would not fit before @p data_offset.
 * @retval RMAP_OK RMAP header initialized successfully.
 */
enum rmap_status rmap_initialize_header_before(
    size_t *header_offset,
    void *raw,
    size_t data_offset,
    enum rmap_packet_type packet_type,
    int command_code,
    size_t reply_address_unpadded_size);

/** Create a success reply header from an existing RMAP command header.
 *
 * Initialize a complete reply header with all fields set to correspond to a
 * success reply based on an existing command header.
 *
 * The reply address will be added before the reply header.
 *
 * It is expected that the caller will update the status field to reflect the
 * actual result of the command verification and execution.
 *
 * If the reply is a read reply or an RMW reply, it is expected that the caller
 * will:
 * - Add the data field.
 * - Add the data CRC.
 * - Update the data length to reflect the actual amount of data in the reply.
 *
 * @pre @p command_header must have been verified to be a valid RMAP command
 *      header.
 *
 * @param[out] raw Destination for the reply packet.
 * @param[out] reply_header_offset Length of the reply address and consequently
 *             the offset of the created reply header in @p raw.
 * @param max_size Maximum number of bytes to write into @p raw.
 * @param[in] command_header Existing RMAP command header.
 *
 * @retval RMAP_NOT_ENOUGH_SPACE @p max_size is less than the size of the reply
 *         address plus header.
 * @retval RMAP_NO_REPLY The command header did not have the reply bit set and
 *         should not result in a reply.
 * @retval RMAP_OK Reply packet created successfully.
 */
enum rmap_status rmap_create_success_reply_from_command(
    void *raw,
    size_t *reply_header_offset,
    size_t max_size,
    const void *command_header);

/** Create a success reply header from an existing RMAP command header, before
 *  existing data.
 *
 * Initialize a complete reply header before existing data, with all fields set
 * to correspond to a success reply based on an existing command header.
 *
 * The reply address will be added before the reply header.
 *
 * It is expected that the caller will update the status field to reflect the
 * actual result of the command verification and execution.
 *
 * If the reply is a read reply or an RMW reply, it is expected that the caller
 * will:
 * - Add the data CRC.
 * - Update the data length to reflect the actual amount of data in the reply.
 *
 * @pre @p command_header must have been verified to be a valid RMAP command
 *      header.
 *
 * @param[out] raw Destination for the reply packet.
 * @param[out] reply_offset Offset of start of reply address from @p raw.
 * @param[out] reply_header_offset Offset of start of header from @p raw.
 * @param data_offset Offset of existing data field from @p raw.
 * @param[in] command_header Existing RMAP command header.
 *
 * @retval RMAP_NOT_ENOUGH_SPACE Reply address and header would not fit before
 *         @p data_offset.
 * @retval RMAP_NO_REPLY The command header did not have the reply bit set and
 *         should not result in a reply.
 * @retval RMAP_OK Reply packet created successfully.
 */
enum rmap_status rmap_create_success_reply_from_command_before(
    void *raw,
    size_t *reply_offset,
    size_t *reply_header_offset,
    size_t data_offset,
    const void *command_header);

/** Get string representation of a status or error constant.
 *
 * Both standardised RMAP status field codes (enum rmap_status_field_code) and
 * library status constants are valid for the @p status parameter.
 *
 * If @p status is neither a standardised RMAP status field code nor a library
 * status constant the string "INVALID_STATUS" will be returned.
 *
 * @param status status or error constant.
 *
 * @return status or error string.
 */
const char *rmap_status_text(int status);

/** Calculate RMAP CRC.
 *
 * @param[in] data Start of data to CRC.
 * @param data_size Size of data to CRC.
 *
 * @return CRC of data.
 */
uint8_t rmap_crc_calculate(const void *data, size_t data_size);

#ifdef __cplusplus
}
#endif

#endif /* RMAP_H */
