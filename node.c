#include "node.h"

#include <assert.h>

enum rmap_status rmap_node_initialize(
    struct rmap_node_context *const context,
    void *const custom_context,
    const struct rmap_node_callbacks *const callbacks,
    const struct rmap_node_initialize_flags flags)
{
    if (!flags.is_target && !flags.is_initiator) {
        return RMAP_NODE_NO_TARGET_OR_INITIATOR;
    }

    context->custom_context = custom_context;
    context->callbacks = *callbacks;
    context->is_target = flags.is_target;
    context->is_initiator = flags.is_initiator;

    context->is_reply_for_unused_packet_type_enabled =
        flags.is_reply_for_unused_packet_type_enabled;

    return RMAP_OK;
}

/** Create and send an error reply to a given command header.
 *
 * Allocate space for, create, and send an error reply based on a given
 * command header and status code.
 *
 * Read and RMW replies (which normally contain data) will have the data length
 * set to 0 and will have a data field with 0 bytes, regardless of the data
 * length in the command header.
 *
 * @pre @p command must have been verified to be a valid RMAP command
 *      header.
 * @pre @p error must be a valid non-success RMAP status field code.
 *
 * @param[in,out] context Node context object.
 * @param[in] command Command header to create reply for.
 * @param error RMAP status field code to use in reply.
 *
 * @retval RMAP_NODE_ALLOCATION_FAILURE Failed to allocate space for reply.
 * @retval RMAP_NODE_SEND_REPLY_FAILURE Failed to send reply.
 * @retval RMAP_OK Reply packet sent successfully.
 */
static enum rmap_status send_error_reply(
    struct rmap_node_context *const context,
    const void *const command,
    const enum rmap_status_field_code error)
{
    size_t header_offset;
    size_t reply_size;

    assert(error != RMAP_STATUS_FIELD_CODE_SUCCESS);

    const size_t reply_size_max =
        RMAP_REPLY_ADDRESS_LENGTH_MAX + RMAP_HEADER_SIZE_MAX + 1;

    uint8_t *const reply_buf =
        context->callbacks.target.allocate(context, reply_size_max);
    if (!reply_buf) {
        return RMAP_NODE_ALLOCATION_FAILURE;
    }

    const enum rmap_status create_reply_status =
        rmap_create_success_reply_from_command(
            reply_buf,
            &header_offset,
            reply_size_max,
            command);
    assert(create_reply_status == RMAP_OK);
    (void)create_reply_status;

    uint8_t *const reply_header = reply_buf + header_offset;

    reply_size = header_offset + rmap_calculate_header_size(reply_header);

    rmap_set_status(reply_header, error);
    if (!rmap_is_write(command)) {
        rmap_set_data_length(reply_header, 0);
        uint8_t *const data =
            reply_header + rmap_calculate_header_size(reply_header);
        data[0] = rmap_crc_calculate(data, 0);
        reply_size += 1;
    }
    rmap_calculate_and_set_header_crc(reply_buf + header_offset);

    const enum rmap_status send_status =
        context->callbacks.target.send_reply(context, reply_buf, reply_size);
    switch (send_status) {
    case RMAP_NODE_SEND_REPLY_FAILURE:
        return send_status;

    default:
        assert(send_status == RMAP_OK);
        break;
    }

    return RMAP_OK;
}

/** Handle incoming write command packet to node.
 *
 * Verify the data field and forward the request for authorization and
 * processing by the user, send reply if relevant.
 *
 * @pre @p packet must have been verified to contain a valid RMAP write command
 *      header.
 * @pre @p size must indicate the exact number of bytes in the write command
 *      packet.
 *
 * @param[in,out] context Node context object.
 * @param[in] packet Incoming packet.
 * @param size Number of bytes in incoming packet in @p packet (excluding the
 *        EOP or EEP).
 * @param has_eep_termination Flag indicating if the incoming packet was
 *        terminated with an EEP.
 *
 * @retval RMAP_NODE_ALLOCATION_FAILURE Incoming packet and intended reply
 *         discarded due to allocation failure.
 * @retval RMAP_NODE_SEND_REPLY_FAILURE Incoming packet and intended reply
 *         discarded due to reply sending failure.
 * @retval RMAP_INSUFFICIENT_DATA Incoming packet rejected due to being smaller
 *         than indicated by the data length. An error reply has been sent if
 *         applicable.
 * @retval RMAP_NODE_INSUFFICIENT_DATA_WITH_EEP Incoming packet (terminated
 *         with an EEP) rejected due to being smaller than indicated by the
 *         data length. An error reply has been sent if applicable.
 * @retval RMAP_TOO_MUCH_DATA Incoming packet rejected due to being larger than
 *         indicated by the data length. An error reply has been sent if
 *         applicable.
 * @retval RMAP_INVALID_DATA_CRC Incoming packet rejected due to the data CRC
 *         indicating errors in the data. An error reply has been sent if
 *         applicable.
 * @retval RMAP_NODE_INVALID_KEY Incoming packet rejected due to its key not
 *         being authorized by the request callback. An error reply has been
 *         sent if applicable.
 * @retval RMAP_NODE_INVALID_TARGET_LOGICAL_ADDRESS Incoming packet rejected
 *         due to its target logical address not being authorized by
 *         the request callback. An error reply has been sent if applicable.
 * @retval RMAP_NODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED Incoming packet
 *         rejected due to not being authorized for "any other reason" by the
 *         request callback. An error reply has been sent if applicable.
 * @retval RMAP_NODE_MEMORY_ACCESS_ERROR Incoming packet processing aborted due
 *         to write memory access error. An error reply has been sent if
 *         applicable.
 * @retval RMAP_OK Incoming packet processed successfully. A reply has been
 *         sent if applicable.
 */
static enum rmap_status handle_write_command(
    struct rmap_node_context *const context,
    const uint8_t *const packet,
    const size_t size,
    const bool has_eep_termination)
{
    enum rmap_status_field_code status_field_code;
    enum rmap_status verify_status;
    size_t reply_header_offset;
    enum rmap_status write_status;

    /* Since the whole packet is available, verification is always done before
     * write regardless.
     *
     * TODO: Should the write still be done before verification in order to
     * match the standard RMAP behaviour?
     */
    status_field_code = RMAP_STATUS_FIELD_CODE_SUCCESS;
    verify_status = rmap_verify_data(packet, size);
    switch (verify_status) {
    case RMAP_INSUFFICIENT_DATA:
        status_field_code = RMAP_STATUS_FIELD_CODE_EARLY_EOP;
        if (has_eep_termination) {
            status_field_code = RMAP_STATUS_FIELD_CODE_EEP;
            verify_status = RMAP_NODE_INSUFFICIENT_DATA_WITH_EEP;
        }
        break;

    case RMAP_TOO_MUCH_DATA:
        status_field_code = RMAP_STATUS_FIELD_CODE_TOO_MUCH_DATA;
        break;

    case RMAP_INVALID_DATA_CRC:
        status_field_code = RMAP_STATUS_FIELD_CODE_INVALID_DATA_CRC;
        break;

    default:
        assert(verify_status == RMAP_OK);
        break;
    }
    if (verify_status != RMAP_OK) {
        if (rmap_is_with_reply(packet)) {
            const enum rmap_status send_status =
                send_error_reply(context, packet, status_field_code);
            switch (send_status) {
            case RMAP_NODE_ALLOCATION_FAILURE:
            case RMAP_NODE_SEND_REPLY_FAILURE:
                return send_status;

            default:
                assert(send_status == RMAP_OK);
                break;
            }
        }
        return verify_status;
    }

    const struct rmap_node_target_request write_request = {
        .target_logical_address = rmap_get_target_logical_address(packet),
        .instruction = rmap_get_instruction(packet),
        .key = rmap_get_key(packet),
        .initiator_logical_address = rmap_get_initiator_logical_address(packet),
        .transaction_identifier = rmap_get_transaction_identifier(packet),
        .extended_address = rmap_get_extended_address(packet),
        .address = rmap_get_address(packet),
        .data_length = rmap_get_data_length(packet)};
    status_field_code = context->callbacks.target.write_request(
        context,
        &write_request,
        packet + rmap_calculate_header_size(packet));
    write_status = RMAP_OK;
    switch (status_field_code) {
    case RMAP_STATUS_FIELD_CODE_INVALID_KEY:
        write_status = RMAP_NODE_INVALID_KEY;
        break;

    case RMAP_STATUS_FIELD_CODE_INVALID_TARGET_LOGICAL_ADDRESS:
        write_status = RMAP_NODE_INVALID_TARGET_LOGICAL_ADDRESS;
        break;

    case RMAP_STATUS_FIELD_CODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED:
        write_status = RMAP_NODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED;
        break;

    case RMAP_STATUS_FIELD_CODE_GENERAL_ERROR_CODE:
        write_status = RMAP_NODE_MEMORY_ACCESS_ERROR;
        break;

    default:
        assert(status_field_code == RMAP_STATUS_FIELD_CODE_SUCCESS);
        break;
    }
    if (status_field_code != RMAP_STATUS_FIELD_CODE_SUCCESS) {
        if (rmap_is_with_reply(packet)) {
            const enum rmap_status send_status =
                send_error_reply(context, packet, status_field_code);
            switch (send_status) {
            case RMAP_NODE_ALLOCATION_FAILURE:
            case RMAP_NODE_SEND_REPLY_FAILURE:
                return send_status;

            default:
                assert(send_status == RMAP_OK);
                break;
            }
        }
        return write_status;
    }

    const size_t reply_maximum_size =
        RMAP_REPLY_ADDRESS_LENGTH_MAX + RMAP_WRITE_REPLY_HEADER_STATIC_SIZE;

    uint8_t *const reply_buf =
        context->callbacks.target.allocate(context, reply_maximum_size);
    if (!reply_buf) {
        return RMAP_NODE_ALLOCATION_FAILURE;
    }

    /* TODO: Might make sense to avoid calculating header CRC here and then
     * recalculate it later?
     */
    const enum rmap_status create_reply_status =
        rmap_create_success_reply_from_command(
            reply_buf,
            &reply_header_offset,
            reply_maximum_size,
            packet);
    assert(create_reply_status == RMAP_OK);
    (void)create_reply_status;

    const size_t reply_size = reply_header_offset +
        rmap_calculate_header_size(reply_buf + reply_header_offset);
    const enum rmap_status send_status =
        context->callbacks.target.send_reply(context, reply_buf, reply_size);
    switch (send_status) {
    case RMAP_NODE_SEND_REPLY_FAILURE:
        return send_status;

    default:
        assert(send_status == RMAP_OK);
        break;
    }

    return RMAP_OK;
}

/** Handle incoming read command packet to node.
 *
 * Forward the request for authorization and processing by the user, send
 * reply.
 *
 * @pre @p packet must have been verified to contain a valid RMAP read command
 *      header.
 *
 * @param[in,out] context Node context object.
 * @param[in] packet Incoming packet.
 *
 * @retval RMAP_NODE_ALLOCATION_FAILURE Incoming packet and intended reply
 *         discarded due to allocation failure.
 * @retval RMAP_NODE_SEND_REPLY_FAILURE Incoming packet and intended reply
 *         discarded due to reply sending failure.
 * @retval RMAP_NODE_INVALID_KEY Incoming packet rejected due to its key not
 *         being authorized by the request callback. An error reply has been
 *         sent.
 * @retval RMAP_NODE_INVALID_TARGET_LOGICAL_ADDRESS Incoming packet rejected
 *         due to its target logical address not being authorized by
 *         the request callback. An error reply has been sent.
 * @retval RMAP_NODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED Incoming packet
 *         rejected due to not being authorized for "any other reason" by the
 *         request callback. An error reply has been sent.
 * @retval RMAP_NODE_MEMORY_ACCESS_ERROR Incoming packet processing aborted due
 *         to read memory access error. An error reply has been sent.
 * @retval RMAP_OK Incoming packet processed successfully. A reply has been
 *         sent if applicable.
 */
static enum rmap_status handle_read_command(
    struct rmap_node_context *const context,
    const uint8_t *const packet)
{
    enum rmap_status_field_code status_field_code;
    size_t reply_header_offset;
    size_t reply_data_size;
    enum rmap_status read_status;

    const size_t reply_maximum_size = RMAP_REPLY_ADDRESS_LENGTH_MAX +
        RMAP_COMMAND_HEADER_STATIC_SIZE + rmap_get_data_length(packet) + 1;

    uint8_t *const reply_buf =
        context->callbacks.target.allocate(context, reply_maximum_size);
    if (!reply_buf) {
        return RMAP_NODE_ALLOCATION_FAILURE;
    }

    /* TODO: Might make sense to avoid calculating header CRC here and then
     * recalculate it later?
     */
    const enum rmap_status create_reply_status =
        rmap_create_success_reply_from_command(
            reply_buf,
            &reply_header_offset,
            reply_maximum_size,
            packet);
    assert(create_reply_status == RMAP_OK);
    (void)create_reply_status;

    const struct rmap_node_target_request read_request = {
        .target_logical_address = rmap_get_target_logical_address(packet),
        .instruction = rmap_get_instruction(packet),
        .key = rmap_get_key(packet),
        .initiator_logical_address = rmap_get_initiator_logical_address(packet),
        .transaction_identifier = rmap_get_transaction_identifier(packet),
        .extended_address = rmap_get_extended_address(packet),
        .address = rmap_get_address(packet),
        .data_length = rmap_get_data_length(packet)};
    const size_t data_offset = reply_header_offset +
        rmap_calculate_header_size(reply_buf + reply_header_offset);
    status_field_code = context->callbacks.target.read_request(
        context,
        reply_buf + data_offset,
        &reply_data_size,
        &read_request);
    read_status = RMAP_OK;
    switch (status_field_code) {
    case RMAP_STATUS_FIELD_CODE_INVALID_KEY:
        read_status = RMAP_NODE_INVALID_KEY;
        break;

    case RMAP_STATUS_FIELD_CODE_INVALID_TARGET_LOGICAL_ADDRESS:
        read_status = RMAP_NODE_INVALID_TARGET_LOGICAL_ADDRESS;
        break;

    case RMAP_STATUS_FIELD_CODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED:
        read_status = RMAP_NODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED;
        break;

    default:
        assert(status_field_code == RMAP_STATUS_FIELD_CODE_SUCCESS);
        if (reply_data_size != read_request.data_length) {
            read_status = RMAP_NODE_MEMORY_ACCESS_ERROR;
        }
        break;
    }

    size_t reply_size;
    if (status_field_code == RMAP_STATUS_FIELD_CODE_SUCCESS) {
        reply_buf[data_offset + reply_data_size] =
            rmap_crc_calculate(reply_buf + data_offset, reply_data_size);
        reply_size = data_offset + reply_data_size + 1;
    } else {
        rmap_set_status(reply_buf + reply_header_offset, status_field_code);
        rmap_set_data_length(reply_buf + reply_header_offset, 0);
        rmap_calculate_and_set_header_crc(reply_buf + reply_header_offset);
        reply_buf[data_offset] = rmap_crc_calculate(reply_buf + data_offset, 0);
        reply_size = data_offset + 1;
    }

    const enum rmap_status send_status =
        context->callbacks.target.send_reply(context, reply_buf, reply_size);
    switch (send_status) {
    case RMAP_NODE_SEND_REPLY_FAILURE:
        return send_status;

    default:
        assert(send_status == RMAP_OK);
        break;
    }

    return read_status;
}

/** Handle incoming RMW command packet to node.
 *
 * Verify the data field and forward the request for authorization and
 * processing by the user, send reply if relevant.
 *
 * @pre @p packet must have been verified to contain a valid RMAP RMW command
 *      header.
 * @pre @p size must indicate the exact number of bytes in the RMW command
 *      packet.
 *
 * @param[in,out] context Node context object.
 * @param[in] packet Incoming packet.
 * @param size Number of bytes in incoming packet in @p packet (excluding the
 *        EOP or EEP).
 * @param has_eep_termination Flag indicating if the incoming packet was
 *        terminated with an EEP.
 *
 * @retval RMAP_NODE_ALLOCATION_FAILURE Incoming packet and intended reply
 *         discarded due to allocation failure.
 * @retval RMAP_NODE_SEND_REPLY_FAILURE Incoming packet and intended reply
 *         discarded due to reply sending failure.
 * @retval RMAP_RMW_DATA_LENGTH_ERROR Incoming packet rejected due to data
 *         length field value being invalid for a RMW command. An error reply
 *         has been sent.
 * @retval RMAP_INSUFFICIENT_DATA Incoming packet rejected due to being smaller
 *         than indicated by the data length. An error reply has been sent.
 * @retval RMAP_NODE_INSUFFICIENT_DATA_WITH_EEP Incoming packet (terminated
 *         with an EEP) rejected due to being smaller than indicated by the
 *         data length. An error reply has been sent.
 * @retval RMAP_TOO_MUCH_DATA Incoming packet rejected due to being larger than
 *         indicated by the data length. An error reply has been sent.
 * @retval RMAP_INVALID_DATA_CRC Incoming packet rejected due to the data CRC
 *         indicating errors in the data. An error reply has been sent.
 * @retval RMAP_NODE_INVALID_KEY Incoming packet rejected due to its key not
 *         being authorized by the request callback. An error reply has been
 *         sent.
 * @retval RMAP_NODE_INVALID_TARGET_LOGICAL_ADDRESS Incoming packet rejected
 *         due to its target logical address not being authorized by
 *         the request callback. An error reply has been sent.
 * @retval RMAP_NODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED Incoming packet
 *         rejected due to not being authorized for "any other reason" by the
 *         request callback. An error reply has been sent.
 * @retval RMAP_NODE_MEMORY_ACCESS_ERROR Incoming packet processing aborted due
 *         to read or write memory access error. An error reply has been sent.
 * @retval RMAP_OK Incoming packet processed successfully. A reply has been
 *         sent if applicable.
 */
static enum rmap_status handle_rmw_command(
    struct rmap_node_context *const context,
    const uint8_t *const packet,
    const size_t size,
    const bool has_eep_termination)
{
    enum rmap_status_field_code status_field_code;
    enum rmap_status verify_status;
    size_t reply_header_offset;
    size_t reply_data_size;
    enum rmap_status rmw_status;

    status_field_code = RMAP_STATUS_FIELD_CODE_SUCCESS;
    verify_status = rmap_verify_data(packet, size);
    switch (verify_status) {
    case RMAP_RMW_DATA_LENGTH_ERROR:
        status_field_code = RMAP_STATUS_FIELD_CODE_RMW_DATA_LENGTH_ERROR;
        break;

    case RMAP_INSUFFICIENT_DATA:
        status_field_code = RMAP_STATUS_FIELD_CODE_EARLY_EOP;
        if (has_eep_termination) {
            status_field_code = RMAP_STATUS_FIELD_CODE_EEP;
            verify_status = RMAP_NODE_INSUFFICIENT_DATA_WITH_EEP;
        }
        break;

    case RMAP_TOO_MUCH_DATA:
        status_field_code = RMAP_STATUS_FIELD_CODE_TOO_MUCH_DATA;
        break;

    case RMAP_INVALID_DATA_CRC:
        status_field_code = RMAP_STATUS_FIELD_CODE_INVALID_DATA_CRC;
        break;

    default:
        assert(verify_status == RMAP_OK);
        break;
    }
    if (verify_status != RMAP_OK) {
        const enum rmap_status send_status =
            send_error_reply(context, packet, status_field_code);
        switch (send_status) {
        case RMAP_NODE_ALLOCATION_FAILURE:
        case RMAP_NODE_SEND_REPLY_FAILURE:
            return send_status;

        default:
            assert(send_status == RMAP_OK);
            break;
        }
        return verify_status;
    }

    const size_t reply_maximum_size = RMAP_REPLY_ADDRESS_LENGTH_MAX +
        RMAP_COMMAND_HEADER_STATIC_SIZE + rmap_get_data_length(packet) / 2 + 1;

    uint8_t *const reply_buf =
        context->callbacks.target.allocate(context, reply_maximum_size);
    if (!reply_buf) {
        return RMAP_NODE_ALLOCATION_FAILURE;
    }

    /* TODO: Might make sense to avoid calculating header CRC here and then
     * recalculate it later?
     */
    const enum rmap_status create_reply_status =
        rmap_create_success_reply_from_command(
            reply_buf,
            &reply_header_offset,
            reply_maximum_size,
            packet);
    assert(create_reply_status == RMAP_OK);
    (void)create_reply_status;
    const size_t data_offset =
        reply_header_offset + RMAP_READ_REPLY_HEADER_STATIC_SIZE;

    const struct rmap_node_target_request rmw_request = {
        .target_logical_address = rmap_get_target_logical_address(packet),
        .instruction = rmap_get_instruction(packet),
        .key = rmap_get_key(packet),
        .initiator_logical_address = rmap_get_initiator_logical_address(packet),
        .transaction_identifier = rmap_get_transaction_identifier(packet),
        .extended_address = rmap_get_extended_address(packet),
        .address = rmap_get_address(packet),
        .data_length = rmap_get_data_length(packet)};
    rmw_status = RMAP_OK;
    status_field_code = context->callbacks.target.rmw_request(
        context,
        reply_buf + data_offset,
        &reply_data_size,
        &rmw_request,
        packet + rmap_calculate_header_size(packet));
    switch (status_field_code) {
    case RMAP_STATUS_FIELD_CODE_INVALID_KEY:
        rmw_status = RMAP_NODE_INVALID_KEY;
        reply_data_size = 0;
        rmap_set_data_length(reply_buf + reply_header_offset, 0);
        break;

    case RMAP_STATUS_FIELD_CODE_INVALID_TARGET_LOGICAL_ADDRESS:
        rmw_status = RMAP_NODE_INVALID_TARGET_LOGICAL_ADDRESS;
        reply_data_size = 0;
        rmap_set_data_length(reply_buf + reply_header_offset, 0);
        break;

    case RMAP_STATUS_FIELD_CODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED:
        rmw_status = RMAP_NODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED;
        reply_data_size = 0;
        rmap_set_data_length(reply_buf + reply_header_offset, 0);
        break;

    case RMAP_STATUS_FIELD_CODE_GENERAL_ERROR_CODE:
        rmw_status = RMAP_NODE_MEMORY_ACCESS_ERROR;
        break;

    default:
        assert(status_field_code == RMAP_STATUS_FIELD_CODE_SUCCESS);
        if (reply_data_size != rmw_request.data_length / 2) {
            rmw_status = RMAP_NODE_MEMORY_ACCESS_ERROR;
        }
        break;
    }

    rmap_set_status(reply_buf + reply_header_offset, status_field_code);
    rmap_calculate_and_set_header_crc(reply_buf + reply_header_offset);
    reply_buf[data_offset + reply_data_size] =
        rmap_crc_calculate(reply_buf + data_offset, reply_data_size);
    const size_t reply_size = data_offset + reply_data_size + 1;

    const enum rmap_status send_status =
        context->callbacks.target.send_reply(context, reply_buf, reply_size);
    switch (send_status) {
    case RMAP_NODE_SEND_REPLY_FAILURE:
        return send_status;

    default:
        assert(send_status == RMAP_OK);
        break;
    }

    return rmw_status;
}

/** Handle incoming command packet to node.
 *
 * Verify header, check if the node accepts commands, verify data field if
 * applicable, and forward the request for authorization and processing by the
 * user, send reply if relevant.
 *
 * @pre @p packet must have been verified to contain a complete RMAP command
 *         header via rmap_verify_header_integrity() and rmap_is_command().
 * @pre @p size must indicate the exact number of bytes in the command packet.
 *
 * @param[in,out] context Node context object.
 * @param[in] packet Incoming packet.
 * @param size Number of bytes in incoming packet in @p packet (excluding the
 *        EOP or EEP).
 * @param has_eep_termination Flag indicating if the incoming packet was
 *        terminated with an EEP.
 *
 * @retval RMAP_NODE_COMMAND_HEADER_FOLLOWED_BY_EEP Incoming command packet
 *         discarded due to valid header being immediately followed by EEP.
 * @retval RMAP_NODE_COMMAND_RECEIVED_BY_INITIATOR Incoming command packet
 *         discarded due to node being configured to reject incoming commands.
 * @retval RMAP_NODE_ALLOCATION_FAILURE Incoming packet and intended reply
 *         discarded due to allocation failure.
 * @retval RMAP_NODE_SEND_REPLY_FAILURE Incoming packet and intended reply
 *         discarded due to reply sending failure.
 * @retval RMAP_UNUSED_PACKET_TYPE Incoming packet rejected due to the packet
 *         type field having the reserved bit set. An error reply may have been
 *         sent, if applicable, depending on the configuration of the node.
 * @retval RMAP_UNUSED_COMMAND_CODE Incoming packet rejected due to the command
 *         field containing a reserved command code.
 * @retval RMAP_INSUFFICIENT_DATA Incoming write or RMW command packet rejected
 *         due to being smaller than indicated by the data length. An error
 *         reply has been sent if applicable.
 * @retval RMAP_NODE_INSUFFICIENT_DATA_WITH_EEP Incoming write or RMW command
 *         packet (terminated with an EEP) rejected due to being smaller than
 *         indicated by the data length. An error reply has been sent if
 *         applicable.
 * @retval RMAP_TOO_MUCH_DATA Incoming write or RMW command packet rejected due
 *         to being larger than indicated by the data length. An error reply
 *         has been sent if applicable.
 * @retval RMAP_INVALID_DATA_CRC Incoming write or RMW command packet rejected
 *         due to the data CRC indicating errors in the data. An error reply
 *         has been sent if applicable.
 * @retval RMAP_RMW_DATA_LENGTH_ERROR Incoming RMW command packet rejected due
 *         to data length field value being invalid for a RMW command. An error
 *         reply has been sent.
 * @retval RMAP_NODE_INVALID_KEY Incoming command packet rejected due to its
 *         key not being authorized by the request callback. An error reply has
 *         been sent if applicable.
 * @retval RMAP_NODE_INVALID_TARGET_LOGICAL_ADDRESS Incoming command packet
 *         rejected due to its target logical address not being authorized by
 *         the request callback. An error reply has been sent if applicable.
 * @retval RMAP_NODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED Incoming command
 *         packet rejected due to not being authorized for "any other reason"
 *         by the request callback. An error reply has been sent if applicable.
 * @retval RMAP_NODE_MEMORY_ACCESS_ERROR Incoming command packet processing
 *         aborted due to write or read memory access error. An error reply has
 *         been sent if applicable.
 * @retval RMAP_OK Incoming packet processed successfully. A reply has been
 *         sent if applicable.
 */
static enum rmap_status handle_command(
    struct rmap_node_context *const context,
    const void *const packet,
    const size_t size,
    const bool has_eep_termination)
{
    if (has_eep_termination && rmap_calculate_header_size(packet) == size) {
        return RMAP_NODE_COMMAND_HEADER_FOLLOWED_BY_EEP;
    }

    if (!context->is_target) {
        return RMAP_NODE_COMMAND_RECEIVED_BY_INITIATOR;
    }

    /* Node is target. */

    const enum rmap_status verify_status =
        rmap_verify_header_instruction(packet);
    switch (verify_status) {
    case RMAP_UNUSED_PACKET_TYPE:
        if (!context->is_reply_for_unused_packet_type_enabled) {
            return verify_status;
        }
        /* Fall through. */
    case RMAP_UNUSED_COMMAND_CODE:
        if (rmap_is_with_reply(packet)) {
            const enum rmap_status send_status = send_error_reply(
                context,
                packet,
                RMAP_STATUS_FIELD_CODE_UNUSED_PACKET_TYPE_OR_COMMAND_CODE);
            switch (send_status) {
            case RMAP_NODE_ALLOCATION_FAILURE:
            case RMAP_NODE_SEND_REPLY_FAILURE:
                return send_status;

            default:
                assert(send_status == RMAP_OK);
                break;
            }
        }
        return verify_status;

    default:
        assert(verify_status == RMAP_OK);
        break;
    }

    if (rmap_is_write(packet)) {
        return handle_write_command(context, packet, size, has_eep_termination);
    }

    if (rmap_is_rmw(packet)) {
        return handle_rmw_command(context, packet, size, has_eep_termination);
    }

    return handle_read_command(context, packet);
}

/** Handle incoming reply packet to node.
 *
 * Verify header, check if the node accepts replies, verify data field if
 * applicable, and forward the reply information to the user.
 *
 * @pre @p packet must have been verified to contain a complete RMAP reply
 *      header via rmap_verify_header_integrity() and rmap_is_reply().
 * @pre @p size must indicate the exact number of bytes in the reply packet.
 *
 * @param[in,out] context Node context object.
 * @param[in] packet Incoming packet.
 * @param size Number of bytes in incoming packet in @p packet.
 *
 * @retval RMAP_NODE_PACKET_ERROR Incoming packet rejected due to one of:
 *         * The packet type field having the reserved bit set.
 *         * The command field containing a reserved command code.
 *         * The command field not having the reply bit set.
 * @retval RMAP_NODE_INVALID_REPLY Incoming packet rejected due to one of:
 *         * The packet being a RMW reply with a data length field value that
 *           is invalid for a RMW reply.
 *         * The packet being smaller than indicated by the data length field.
 *         * The packet being larger than indicated by the data length field.
 *         * The data CRC indicating errors in the data.
 * @retval RMAP_OK Incoming packet processed successfully.
 */
static enum rmap_status handle_reply(
    struct rmap_node_context *const context,
    const uint8_t *const packet,
    const size_t size)
{
    enum rmap_status status;

    if (!context->is_initiator) {
        return RMAP_NODE_REPLY_RECEIVED_BY_TARGET;
    }

    /* Node is initiator. */

    status = rmap_verify_header_instruction(packet);
    switch (status) {
    case RMAP_UNUSED_PACKET_TYPE:
    case RMAP_NO_REPLY:
    case RMAP_UNUSED_COMMAND_CODE:
        /* TODO: Is this merging really a good idea? It matches the standard,
         * but would it make sense to provide more information?
         */
        return RMAP_NODE_PACKET_ERROR;

    default:
        assert(status == RMAP_OK);
        break;
    }

    if (rmap_is_write(packet)) {
        context->callbacks.initiator.received_write_reply(
            context,
            rmap_get_transaction_identifier(packet),
            rmap_get_status(packet));
        return RMAP_OK;
    }

    /* Read or RMW. */

    status = rmap_verify_data(packet, size);
    switch (status) {
    case RMAP_RMW_DATA_LENGTH_ERROR:
    case RMAP_INSUFFICIENT_DATA:
    case RMAP_TOO_MUCH_DATA:
    case RMAP_INVALID_DATA_CRC:
        /* TODO: Is this merging really a good idea? It matches the standard,
         * but would it make sense to provide more information?
         */
        return RMAP_NODE_INVALID_REPLY;

    default:
        assert(status == RMAP_OK);
        break;
    }

    if (rmap_is_rmw(packet)) {
        context->callbacks.initiator.received_rmw_reply(
            context,
            rmap_get_transaction_identifier(packet),
            rmap_get_status(packet),
            packet + rmap_calculate_header_size(packet),
            size - rmap_calculate_header_size(packet) - 1);
        return RMAP_OK;
    }

    /* Read. */

    context->callbacks.initiator.received_read_reply(
        context,
        rmap_get_transaction_identifier(packet),
        rmap_get_status(packet),
        packet + rmap_calculate_header_size(packet),
        size - rmap_calculate_header_size(packet) - 1);

    return RMAP_OK;
}

enum rmap_status rmap_node_handle_incoming(
    struct rmap_node_context *const context,
    const void *const packet,
    const size_t size,
    const bool has_eep_termination)
{
    enum rmap_status status;

    status = rmap_verify_header_integrity(packet, size);
    switch (status) {
    case RMAP_NO_RMAP_PROTOCOL:
    case RMAP_INCOMPLETE_HEADER:
    case RMAP_HEADER_CRC_ERROR:
        return status;

    default:
        assert(status == RMAP_OK);
        break;
    }

    if (rmap_is_command(packet)) {
        return handle_command(context, packet, size, has_eep_termination);
    }

    return handle_reply(context, packet, size);
}
