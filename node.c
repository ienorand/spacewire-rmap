#include "node.h"

#include <assert.h>

void rmap_node_initialize(
    struct rmap_node_context *const context,
    void *const custom_context,
    const struct rmap_node_callbacks *const callbacks,
    const struct rmap_node_initialize_flags flags,
    const struct rmap_node_target_callbacks *const target_callbacks,
    const struct rmap_node_initiator_callbacks *const initiator_callbacks)
{
    context->custom_context = custom_context;
    context->callbacks = *callbacks;
    context->is_target = flags.is_target;
    context->is_initator = flags.is_initator;

    context->target.error_information = RMAP_OK;
    context->target.callbacks = *target_callbacks;
    context->target.is_reply_for_unused_packet_type_enabled =
        flags.is_reply_for_unused_packet_type_enabled;

    context->initiator.error_information = RMAP_OK;
    context->initiator.callbacks = *initiator_callbacks;
}

static void send_error_reply(
    struct rmap_node_context *const context,
    const void *const command,
    const enum rmap_status_field_code error)
{
    enum rmap_status status;
    size_t header_offset;
    size_t reply_size;

    const size_t reply_size_max =
        RMAP_REPLY_ADDRESS_LENGTH_MAX + RMAP_HEADER_SIZE_MAX;

    uint8_t *const reply_buf =
        context->callbacks.allocate(context, reply_size_max);

    status = rmap_create_success_reply_from_command(
        reply_buf,
        &header_offset,
        reply_size_max,
        command);
    assert(status == RMAP_OK);
    (void)status;

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

    context->target.callbacks.send_reply(context, reply_buf, reply_size);
}

static void handle_write_command(
    struct rmap_node_context *const context,
    const uint8_t *const packet,
    const size_t size)
{
    enum rmap_status status;
    enum rmap_status_field_code status_field_code;
    size_t reply_header_offset;

    /* Since the whole packet is available, verification is always done before
     * write regardless.
     *
     * TODO: Should the write still be done before verification in order to
     * match the standard RMAP behaviour?
     */
    status_field_code = RMAP_STATUS_FIELD_CODE_SUCCESS;
    status = rmap_verify_data(packet, size);
    switch (status) {
    case RMAP_INSUFFICIENT_DATA:
        context->target.error_information = RMAP_INSUFFICIENT_DATA;
        status_field_code = RMAP_STATUS_FIELD_CODE_EARLY_EOP;
        break;

    case RMAP_TOO_MUCH_DATA:
        context->target.error_information = RMAP_TOO_MUCH_DATA;
        status_field_code = RMAP_STATUS_FIELD_CODE_TOO_MUCH_DATA;
        break;

    case RMAP_INVALID_DATA_CRC:
        context->target.error_information = RMAP_INVALID_DATA_CRC;
        status_field_code = RMAP_STATUS_FIELD_CODE_INVALID_DATA_CRC;
        break;

    default:
        assert(status == RMAP_OK);
        break;
    }
    if (status_field_code != RMAP_STATUS_FIELD_CODE_SUCCESS) {
        if (rmap_is_with_reply(packet)) {
            send_error_reply(context, packet, status_field_code);
        }
        return;
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
    status_field_code = context->target.callbacks.write_request(
        context,
        &write_request,
        packet + rmap_calculate_header_size(packet));
    if (status_field_code != RMAP_STATUS_FIELD_CODE_SUCCESS) {
        if (rmap_is_with_reply(packet)) {
            send_error_reply(context, packet, status_field_code);
        }
        return;
    }

    const size_t reply_size_max =
        RMAP_REPLY_ADDRESS_LENGTH_MAX + RMAP_HEADER_SIZE_MAX;

    uint8_t *const reply_buf =
        context->callbacks.allocate(context, reply_size_max);

    status = rmap_create_success_reply_from_command(
        reply_buf,
        &reply_header_offset,
        reply_size_max,
        packet);
    assert(status == RMAP_OK);

    context->target.callbacks.send_reply(
        context,
        reply_buf,
        reply_header_offset +
            rmap_calculate_header_size(reply_buf + reply_header_offset));
}

static void handle_read_command(
    struct rmap_node_context *const context,
    const uint8_t *const packet)
{
    enum rmap_status status;
    enum rmap_status_field_code status_field_code;
    size_t reply_offset;
    size_t reply_header_offset;
    size_t reply_data_size;

    const size_t data_offset =
        RMAP_REPLY_ADDRESS_LENGTH_MAX + RMAP_HEADER_SIZE_MAX;
    const size_t reply_size_max =
        data_offset + rmap_get_data_length(packet) + 1;

    uint8_t *const reply_buf =
        context->callbacks.allocate(context, reply_size_max);

    const struct rmap_node_target_request read_request = {
        .target_logical_address = rmap_get_target_logical_address(packet),
        .instruction = rmap_get_instruction(packet),
        .key = rmap_get_key(packet),
        .initiator_logical_address = rmap_get_initiator_logical_address(packet),
        .transaction_identifier = rmap_get_transaction_identifier(packet),
        .extended_address = rmap_get_extended_address(packet),
        .address = rmap_get_address(packet),
        .data_length = rmap_get_data_length(packet)};
    status_field_code = context->target.callbacks.read_request(
        context,
        reply_buf + data_offset,
        &reply_data_size,
        &read_request);

    status = rmap_create_success_reply_from_command_before(
        reply_buf,
        &reply_offset,
        &reply_header_offset,
        data_offset,
        packet);
    assert(status == RMAP_OK);
    (void)status;

    if (status_field_code == RMAP_STATUS_FIELD_CODE_SUCCESS) {
        reply_buf[data_offset + rmap_get_data_length(packet)] =
            rmap_crc_calculate(
                reply_buf + data_offset,
                rmap_get_data_length(packet));
    } else {
        rmap_set_status(reply_buf + reply_header_offset, status_field_code);
        rmap_set_data_length(reply_buf + reply_header_offset, 0);
        rmap_calculate_and_set_header_crc(reply_buf + reply_header_offset);
        reply_buf[data_offset] = rmap_crc_calculate(reply_buf + data_offset, 0);
    }

    context->target.callbacks.send_reply(
        context,
        reply_buf + reply_offset,
        data_offset + rmap_get_data_length(reply_buf + reply_header_offset) +
            1);
}

static void handle_rmw_command(
    struct rmap_node_context *const context,
    const uint8_t *const packet,
    const size_t size)
{
    enum rmap_status status;
    enum rmap_status_field_code status_field_code;
    size_t reply_offset;
    size_t reply_header_offset;
    size_t reply_data_size;

    status = rmap_verify_data(packet, size);
    switch (status) {
    case RMAP_RMW_DATA_LENGTH_ERROR:
        context->target.error_information = RMAP_RMW_DATA_LENGTH_ERROR;
        send_error_reply(
            context,
            packet,
            RMAP_STATUS_FIELD_CODE_RMW_DATA_LENGTH_ERROR);
        return;

    case RMAP_INSUFFICIENT_DATA:
        context->target.error_information = RMAP_INSUFFICIENT_DATA;
        send_error_reply(context, packet, RMAP_STATUS_FIELD_CODE_EARLY_EOP);
        return;

    case RMAP_TOO_MUCH_DATA:
        context->target.error_information = RMAP_TOO_MUCH_DATA;
        send_error_reply(context, packet, RMAP_STATUS_FIELD_CODE_TOO_MUCH_DATA);
        return;

    case RMAP_INVALID_DATA_CRC:
        context->target.error_information = RMAP_INVALID_DATA_CRC;
        send_error_reply(
            context,
            packet,
            RMAP_STATUS_FIELD_CODE_INVALID_DATA_CRC);
        return;

    default:
        assert(status == RMAP_OK);
        break;
    }

    const size_t data_offset =
        RMAP_REPLY_ADDRESS_LENGTH_MAX + RMAP_HEADER_SIZE_MAX;
    const size_t reply_size_max =
        data_offset + rmap_get_data_length(packet) + 1;

    uint8_t *const reply_buf =
        context->callbacks.allocate(context, reply_size_max);

    const struct rmap_node_target_request rmw_request = {
        .target_logical_address = rmap_get_target_logical_address(packet),
        .instruction = rmap_get_instruction(packet),
        .key = rmap_get_key(packet),
        .initiator_logical_address = rmap_get_initiator_logical_address(packet),
        .transaction_identifier = rmap_get_transaction_identifier(packet),
        .extended_address = rmap_get_extended_address(packet),
        .address = rmap_get_address(packet),
        .data_length = rmap_get_data_length(packet)};
    status_field_code = context->target.callbacks.rmw_request(
        context,
        reply_buf + data_offset,
        &reply_data_size,
        &rmw_request,
        packet + rmap_calculate_header_size(packet));

    status = rmap_create_success_reply_from_command_before(
        reply_buf,
        &reply_offset,
        &reply_header_offset,
        data_offset,
        packet);
    assert(status == RMAP_OK);

    if (status_field_code == RMAP_STATUS_FIELD_CODE_SUCCESS) {
        reply_buf[data_offset + rmap_get_data_length(packet)] =
            rmap_crc_calculate(
                reply_buf + data_offset,
                rmap_get_data_length(packet));
    } else {
        rmap_set_status(reply_buf + reply_header_offset, status_field_code);
        rmap_set_data_length(reply_buf + reply_header_offset, 0);
        rmap_calculate_and_set_header_crc(reply_buf + reply_header_offset);
        reply_buf[data_offset] = rmap_crc_calculate(reply_buf + data_offset, 0);
    }

    context->target.callbacks.send_reply(
        context,
        reply_buf + reply_offset,
        data_offset + rmap_get_data_length(reply_buf + reply_header_offset) +
            1);
}

static void handle_command(
    struct rmap_node_context *const context,
    const void *const packet,
    const size_t size)
{
    enum rmap_status status;

    if (!context->is_target) {
        if (context->is_initator) {
            context->target.error_information =
                RMAP_COMMAND_RECEIVED_BY_INITIATOR;
        }
        return;
    }

    /* Node is target. */

    status = rmap_verify_header_instruction(packet);
    switch (status) {
    case RMAP_UNUSED_PACKET_TYPE:
        context->initiator.error_information = RMAP_UNUSED_PACKET_TYPE;
        if (context->target.is_reply_for_unused_packet_type_enabled) {
            send_error_reply(
                context,
                packet,
                RMAP_STATUS_FIELD_CODE_UNUSED_PACKET_TYPE_OR_COMMAND_CODE);
        }
        return;

    case RMAP_UNUSED_COMMAND_CODE:
        context->initiator.error_information = RMAP_UNUSED_COMMAND_CODE;
        send_error_reply(
            context,
            packet,
            RMAP_STATUS_FIELD_CODE_UNUSED_PACKET_TYPE_OR_COMMAND_CODE);
        return;

    default:
        assert(status == RMAP_OK);
        break;
    }

    if (rmap_is_write(packet)) {
        handle_write_command(context, packet, size);
        return;
    }

    if (rmap_is_rmw(packet)) {
        handle_rmw_command(context, packet, size);
    }

    handle_read_command(context, packet);
}

static void handle_reply(
    struct rmap_node_context *const context,
    const uint8_t *const packet,
    const size_t size)
{
    enum rmap_status status;

    if (!context->is_initator) {
        if (context->is_target) {
            context->target.error_information = RMAP_REPLY_RECEIVED_BY_TARGET;
        }
        return;
    }

    /* Node is initiator. */

    status = rmap_verify_header_instruction(packet);
    switch (status) {
    case RMAP_UNUSED_PACKET_TYPE:
    case RMAP_NO_REPLY:
        context->initiator.error_information = RMAP_INVALID_REPLY;
        return;

    case RMAP_UNUSED_COMMAND_CODE:
        context->initiator.error_information = RMAP_PACKET_ERROR;
        return;

    default:
        assert(status == RMAP_OK);
        break;
    }

    if (rmap_is_write(packet)) {
        context->initiator.callbacks.received_write_reply(
            context,
            rmap_get_transaction_identifier(packet),
            rmap_get_status(packet));
        return;
    }

    /* Read or RMW. */

    status = rmap_verify_data(packet, size);
    switch (status) {
    case RMAP_RMW_DATA_LENGTH_ERROR:
    case RMAP_INSUFFICIENT_DATA:
    case RMAP_TOO_MUCH_DATA:
    case RMAP_INVALID_DATA_CRC:
        context->initiator.error_information = RMAP_INVALID_REPLY;
        return;

    default:
        assert(status == RMAP_OK);
        break;
    }

    if (rmap_is_rmw(packet)) {
        context->initiator.callbacks.received_rmw_reply(
            context,
            rmap_get_transaction_identifier(packet),
            rmap_get_status(packet),
            packet + rmap_calculate_header_size(packet),
            size - rmap_calculate_header_size(packet) - 1);
        return;
    }

    /* Read. */

    context->initiator.callbacks.received_read_reply(
        context,
        rmap_get_transaction_identifier(packet),
        rmap_get_status(packet),
        packet + rmap_calculate_header_size(packet),
        size - rmap_calculate_header_size(packet) - 1);
}

void rmap_node_target_handle_incoming(
    struct rmap_node_context *const context,
    const void *const packet,
    const size_t size)
{
    enum rmap_status status;

    status = rmap_verify_header_integrity(packet, size);
    switch (status) {
    case RMAP_NO_RMAP_PROTOCOL:
        return;

    case RMAP_INCOMPLETE_HEADER:
    case RMAP_HEADER_CRC_ERROR:
        if (context->is_target) {
            context->target.error_information = status;
        }
        if (context->is_initator) {
            context->initiator.error_information = status;
        }
        return;

    default:
        assert(status == RMAP_OK);
        break;
    };

    if (rmap_is_command(packet)) {
        handle_command(context, packet, size);
        return;
    }

    handle_reply(context, packet, size);
}
