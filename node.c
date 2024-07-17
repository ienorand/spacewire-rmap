#include "node.h"

#include <assert.h>

/* Input must be a valid command header. */
static size_t
calculate_success_reply_size_from_command(const void *const command_header)
{
    /* TODO:
     * Maybe expose rmap_calculate_reply_address_size() or
     * rmap_calculate_theoretical_header_size()?
     */
    uint8_t reply_address[RMAP_REPLY_ADDRESS_LENGTH_MAX];
    size_t reply_address_size;
    const enum rmap_status status = rmap_get_reply_address(
        reply_address,
        &reply_address_size,
        sizeof(reply_address),
        command_header);
    assert(status == RMAP_OK);
    (void)status;

    if (rmap_is_write(command_header)) {
        return reply_address_size + RMAP_WRITE_REPLY_HEADER_STATIC_SIZE;
    }

    /* Read or RMW. */

    return reply_address_size + RMAP_READ_REPLY_HEADER_STATIC_SIZE +
        rmap_get_data_length(command_header) + 1;
}

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

static enum rmap_status send_error_reply(
    struct rmap_node_context *const context,
    const void *const command,
    const enum rmap_status_field_code error)
{
    size_t header_offset;
    size_t reply_size;

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

static enum rmap_status handle_write_command(
    struct rmap_node_context *const context,
    const uint8_t *const packet,
    const size_t size)
{
    enum rmap_status_field_code status_field_code;
    size_t reply_header_offset;
    enum rmap_status write_status;

    /* Since the whole packet is available, verification is always done before
     * write regardless.
     *
     * TODO: Should the write still be done before verification in order to
     * match the standard RMAP behaviour?
     */
    status_field_code = RMAP_STATUS_FIELD_CODE_SUCCESS;
    const enum rmap_status verify_status = rmap_verify_data(packet, size);
    switch (verify_status) {
    case RMAP_INSUFFICIENT_DATA:
        status_field_code = RMAP_STATUS_FIELD_CODE_EARLY_EOP;
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

    const size_t reply_size = calculate_success_reply_size_from_command(packet);

    uint8_t *const reply_buf =
        context->callbacks.target.allocate(context, reply_size);
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
            reply_size,
            packet);
    assert(create_reply_status == RMAP_OK);
    (void)create_reply_status;
    assert(
        reply_header_offset +
            rmap_calculate_header_size(reply_buf + reply_header_offset) ==
        reply_size);

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

static enum rmap_status handle_read_command(
    struct rmap_node_context *const context,
    const uint8_t *const packet)
{
    enum rmap_status_field_code status_field_code;
    size_t reply_header_offset;
    size_t reply_data_size;
    enum rmap_status read_status;

    const size_t reply_maximum_size =
        calculate_success_reply_size_from_command(packet);

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
    assert(
        reply_header_offset +
            rmap_calculate_header_size(reply_buf + reply_header_offset) +
            rmap_get_data_length(packet) + 1 ==
        reply_maximum_size);

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

static enum rmap_status handle_rmw_command(
    struct rmap_node_context *const context,
    const uint8_t *const packet,
    const size_t size)
{
    enum rmap_status_field_code status_field_code;
    size_t reply_header_offset;
    size_t reply_data_size;
    enum rmap_status rmw_status;

    status_field_code = RMAP_STATUS_FIELD_CODE_SUCCESS;
    const enum rmap_status verify_status = rmap_verify_data(packet, size);
    switch (verify_status) {
    case RMAP_RMW_DATA_LENGTH_ERROR:
        status_field_code = RMAP_STATUS_FIELD_CODE_RMW_DATA_LENGTH_ERROR;
        break;

    case RMAP_INSUFFICIENT_DATA:
        status_field_code = RMAP_STATUS_FIELD_CODE_EARLY_EOP;
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

    const size_t reply_maximum_size =
        calculate_success_reply_size_from_command(packet);

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
    assert(
        data_offset + rmap_get_data_length(packet) + 1 == reply_maximum_size);

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

    case RMAP_OK:
        return rmw_status;

    default:
        assert(send_status == RMAP_OK);
        break;
    }

    return rmw_status;
}

static enum rmap_status handle_command(
    struct rmap_node_context *const context,
    const void *const packet,
    const size_t size)
{
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
        return handle_write_command(context, packet, size);
    }

    if (rmap_is_rmw(packet)) {
        return handle_rmw_command(context, packet, size);
    }

    return handle_read_command(context, packet);
}

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

/* TODO: How to handle EEP? Should this be passed to incoming and on to
 * handle_write_command() and handle_rmw_command() and acted upon if located in
 * data?
 */
enum rmap_status rmap_node_handle_incoming(
    struct rmap_node_context *const context,
    const void *const packet,
    const size_t size)
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
    };

    if (rmap_is_command(packet)) {
        return handle_command(context, packet, size);
    }

    return handle_reply(context, packet, size);
}
