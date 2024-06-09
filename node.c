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

void rmap_node_initialize(
    struct rmap_node_context *const context,
    void *const custom_context,
    const struct rmap_node_callbacks *const callbacks,
    const struct rmap_node_initialize_flags flags)
{
    context->custom_context = custom_context;
    context->callbacks = *callbacks;
    context->is_target = flags.is_target;
    context->is_initiator = flags.is_initiator;

    context->error_information = RMAP_NODE_OK;
    context->is_reply_for_unused_packet_type_enabled =
        flags.is_reply_for_unused_packet_type_enabled;

    context->error_information = RMAP_NODE_OK;
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
        context->callbacks.target.allocate(context, reply_size_max);
    if (!reply_buf) {
        context->error_information = RMAP_NODE_ALLOCATION_FAILURE;
        return;
    }

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

    context->callbacks.target.send_reply(context, reply_buf, reply_size);
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
        context->error_information = RMAP_NODE_INSUFFICIENT_DATA;
        status_field_code = RMAP_STATUS_FIELD_CODE_EARLY_EOP;
        break;

    case RMAP_TOO_MUCH_DATA:
        context->error_information = RMAP_NODE_TOO_MUCH_DATA;
        status_field_code = RMAP_STATUS_FIELD_CODE_TOO_MUCH_DATA;
        break;

    case RMAP_INVALID_DATA_CRC:
        context->error_information = RMAP_NODE_INVALID_DATA_CRC;
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
    status_field_code = context->callbacks.target.write_request(
        context,
        &write_request,
        packet + rmap_calculate_header_size(packet));
    switch (status_field_code) {
    case RMAP_STATUS_FIELD_CODE_INVALID_KEY:
        context->error_information = RMAP_NODE_INVALID_KEY;
        break;

    case RMAP_STATUS_FIELD_CODE_INVALID_TARGET_LOGICAL_ADDRESS:
        context->error_information = RMAP_NODE_INVALID_TARGET_LOGICAL_ADDRESS;
        break;

    case RMAP_STATUS_FIELD_CODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED:
        context->error_information =
            RMAP_NODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED;
        break;

    case RMAP_STATUS_FIELD_CODE_GENERAL_ERROR_CODE:
        context->error_information = RMAP_NODE_MEMORY_ACCESS_ERROR;
        break;

    default:
        assert(status_field_code == RMAP_STATUS_FIELD_CODE_SUCCESS);
        break;
    }
    if (status_field_code != RMAP_STATUS_FIELD_CODE_SUCCESS) {
        if (rmap_is_with_reply(packet)) {
            send_error_reply(context, packet, status_field_code);
        }
        return;
    }

    const size_t reply_size = calculate_success_reply_size_from_command(packet);

    uint8_t *const reply_buf =
        context->callbacks.target.allocate(context, reply_size);
    if (!reply_buf) {
        context->error_information = RMAP_NODE_ALLOCATION_FAILURE;
        return;
    }

    status = rmap_create_success_reply_from_command(
        reply_buf,
        &reply_header_offset,
        reply_size,
        packet);
    assert(status == RMAP_OK);
    (void)status;
    assert(
        reply_header_offset +
            rmap_calculate_header_size(reply_buf + reply_header_offset) ==
        reply_size);

    context->callbacks.target.send_reply(context, reply_buf, reply_size);
}

static void handle_read_command(
    struct rmap_node_context *const context,
    const uint8_t *const packet)
{
    enum rmap_status status;
    enum rmap_status_field_code status_field_code;
    size_t reply_header_offset;
    size_t reply_data_size;

    const size_t reply_maximum_size =
        calculate_success_reply_size_from_command(packet);

    uint8_t *const reply_buf =
        context->callbacks.target.allocate(context, reply_maximum_size);
    if (!reply_buf) {
        context->error_information = RMAP_NODE_ALLOCATION_FAILURE;
        return;
    }

    status = rmap_create_success_reply_from_command(
        reply_buf,
        &reply_header_offset,
        reply_maximum_size,
        packet);
    assert(status == RMAP_OK);
    (void)status;
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
    switch (status_field_code) {
    case RMAP_STATUS_FIELD_CODE_INVALID_KEY:
        context->error_information = RMAP_NODE_INVALID_KEY;
        break;

    case RMAP_STATUS_FIELD_CODE_INVALID_TARGET_LOGICAL_ADDRESS:
        context->error_information = RMAP_NODE_INVALID_TARGET_LOGICAL_ADDRESS;
        break;

    case RMAP_STATUS_FIELD_CODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED:
        context->error_information =
            RMAP_NODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED;
        break;

    case RMAP_STATUS_FIELD_CODE_GENERAL_ERROR_CODE:
        context->error_information = RMAP_NODE_MEMORY_ACCESS_ERROR;
        break;

    default:
        assert(status_field_code == RMAP_STATUS_FIELD_CODE_SUCCESS);
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

    context->callbacks.target.send_reply(context, reply_buf, reply_size);
}

static void handle_rmw_command(
    struct rmap_node_context *const context,
    const uint8_t *const packet,
    const size_t size)
{
    enum rmap_status status;
    enum rmap_status_field_code status_field_code;
    size_t reply_header_offset;
    size_t reply_data_size;

    status = rmap_verify_data(packet, size);
    switch (status) {
    case RMAP_RMW_DATA_LENGTH_ERROR:
        context->error_information = RMAP_NODE_RMW_DATA_LENGTH_ERROR;
        send_error_reply(
            context,
            packet,
            RMAP_STATUS_FIELD_CODE_RMW_DATA_LENGTH_ERROR);
        return;

    case RMAP_INSUFFICIENT_DATA:
        context->error_information = RMAP_NODE_INSUFFICIENT_DATA;
        send_error_reply(context, packet, RMAP_STATUS_FIELD_CODE_EARLY_EOP);
        return;

    case RMAP_TOO_MUCH_DATA:
        context->error_information = RMAP_NODE_TOO_MUCH_DATA;
        send_error_reply(context, packet, RMAP_STATUS_FIELD_CODE_TOO_MUCH_DATA);
        return;

    case RMAP_INVALID_DATA_CRC:
        context->error_information = RMAP_NODE_INVALID_DATA_CRC;
        send_error_reply(
            context,
            packet,
            RMAP_STATUS_FIELD_CODE_INVALID_DATA_CRC);
        return;

    default:
        assert(status == RMAP_OK);
        break;
    }

    const size_t reply_maximum_size =
        calculate_success_reply_size_from_command(packet);

    uint8_t *const reply_buf =
        context->callbacks.target.allocate(context, reply_maximum_size);
    if (!reply_buf) {
        context->error_information = RMAP_NODE_ALLOCATION_FAILURE;
        return;
    }

    status = rmap_create_success_reply_from_command(
        reply_buf,
        &reply_header_offset,
        reply_maximum_size,
        packet);
    assert(status == RMAP_OK);
    (void)status;
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
    status_field_code = context->callbacks.target.rmw_request(
        context,
        reply_buf + data_offset,
        &reply_data_size,
        &rmw_request,
        packet + rmap_calculate_header_size(packet));
    switch (status_field_code) {
    case RMAP_STATUS_FIELD_CODE_INVALID_KEY:
        context->error_information = RMAP_NODE_INVALID_KEY;
        break;

    case RMAP_STATUS_FIELD_CODE_INVALID_TARGET_LOGICAL_ADDRESS:
        context->error_information = RMAP_NODE_INVALID_TARGET_LOGICAL_ADDRESS;
        break;

    case RMAP_STATUS_FIELD_CODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED:
        context->error_information =
            RMAP_NODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED;
        break;

    case RMAP_STATUS_FIELD_CODE_GENERAL_ERROR_CODE:
        context->error_information = RMAP_NODE_MEMORY_ACCESS_ERROR;
        break;

    default:
        assert(status_field_code == RMAP_STATUS_FIELD_CODE_SUCCESS);
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

    context->callbacks.target.send_reply(context, reply_buf, reply_size);
}

static void handle_command(
    struct rmap_node_context *const context,
    const void *const packet,
    const size_t size)
{
    enum rmap_status status;

    if (!context->is_target) {
        if (context->is_initiator) {
            context->error_information =
                RMAP_NODE_COMMAND_RECEIVED_BY_INITIATOR;
        }
        return;
    }

    /* Node is target. */

    status = rmap_verify_header_instruction(packet);
    switch (status) {
    case RMAP_UNUSED_PACKET_TYPE:
        context->error_information =
            RMAP_NODE_UNUSED_PACKET_TYPE_OR_COMMAND_CODE;
        if (context->is_reply_for_unused_packet_type_enabled) {
            send_error_reply(
                context,
                packet,
                RMAP_STATUS_FIELD_CODE_UNUSED_PACKET_TYPE_OR_COMMAND_CODE);
        }
        return;

    case RMAP_UNUSED_COMMAND_CODE:
        context->error_information =
            RMAP_NODE_UNUSED_PACKET_TYPE_OR_COMMAND_CODE;
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
        return;
    }

    handle_read_command(context, packet);
}

static void handle_reply(
    struct rmap_node_context *const context,
    const uint8_t *const packet,
    const size_t size)
{
    enum rmap_status status;

    if (!context->is_initiator) {
        if (context->is_target) {
            context->error_information = RMAP_NODE_REPLY_RECEIVED_BY_TARGET;
        }
        return;
    }

    /* Node is initiator. */

    status = rmap_verify_header_instruction(packet);
    switch (status) {
    case RMAP_UNUSED_PACKET_TYPE:
    case RMAP_NO_REPLY:
        context->error_information = RMAP_NODE_INVALID_REPLY;
        return;

    case RMAP_UNUSED_COMMAND_CODE:
        context->error_information = RMAP_NODE_PACKET_ERROR;
        return;

    default:
        assert(status == RMAP_OK);
        break;
    }

    if (rmap_is_write(packet)) {
        context->callbacks.initiator.received_write_reply(
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
        context->error_information = RMAP_NODE_INVALID_REPLY;
        return;

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
        return;
    }

    /* Read. */

    context->callbacks.initiator.received_read_reply(
        context,
        rmap_get_transaction_identifier(packet),
        rmap_get_status(packet),
        packet + rmap_calculate_header_size(packet),
        size - rmap_calculate_header_size(packet) - 1);
}

/* TODO: How to handle EEP? Should this be passed to incoming and on to
 * handle_write_command() and handle_rmw_command() and acted upon if located in
 * data?
 */
void rmap_node_handle_incoming(
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
        /* TODO: Would need to report EEP instead if relevant. */
        if (context->is_target) {
            context->error_information = RMAP_NODE_EARLY_EOP;
        }
        if (context->is_initiator) {
            context->error_information = RMAP_NODE_EARLY_EOP;
        }
        return;

    case RMAP_HEADER_CRC_ERROR:
        if (context->is_target) {
            context->error_information = RMAP_NODE_HEADER_CRC_ERROR;
        }
        if (context->is_initiator) {
            context->error_information = RMAP_NODE_HEADER_CRC_ERROR;
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
