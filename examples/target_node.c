/** Examples showing a target and initiator node. */

#include "node.h"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct custom_context {
    uint8_t *target_memory;
    uint64_t target_memory_start_address;
    size_t target_memory_size;
    uint8_t target_logical_address;
    uint8_t target_key;
};

static void *allocate(
    struct rmap_node *const node,
    void *const transaction_custom_context,
    const size_t size)
{
    (void)node;
    (void)transaction_custom_context;

    return malloc(size);
}

static void print_data(const void *const data, const size_t size)
{
    const unsigned char *const data_bytes = data;
    for (size_t i = 0; i < size; ++i) {
        printf("%02X ", data_bytes[i]);
    }
    printf("\n");
}

static enum rmap_status send_reply(
    struct rmap_node *const node,
    void *const transaction_custom_context,
    void *const packet,
    const size_t size)
{
    (void)node;
    (void)transaction_custom_context;

    printf("Sending reply with size %zu:\n", size);
    print_data(packet, size);
    free(packet);

    return RMAP_OK;
}

static enum rmap_status_field_code write_request(
    struct rmap_node *const node,
    void *const transaction_custom_context,
    const struct rmap_node_target_request *const request,
    const void *const data)
{
    (void)transaction_custom_context;

    printf("Processing write request\n");
    struct custom_context *const custom_context = node->custom_context;

    if (request->key != custom_context->target_key) {
        printf("Rejecting write request due to invalid key\n");
        return RMAP_STATUS_FIELD_CODE_INVALID_KEY;
    }

    if (request->target_logical_address !=
        custom_context->target_logical_address) {
        printf("Rejecting write request due to invalid logical address\n");
        return RMAP_STATUS_FIELD_CODE_INVALID_TARGET_LOGICAL_ADDRESS;
    }

    /* This implementation writes bytewise and has no alignment requirements. */

    const uint64_t start_address =
        (uint64_t)request->extended_address << 32 | request->address;

    if (start_address < custom_context->target_memory_start_address ||
        start_address > custom_context->target_memory_start_address +
                custom_context->target_memory_size - 1) {
        printf(
            "Rejecting write request due to address outside target memory\n");
        return RMAP_STATUS_FIELD_CODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED;
    }

    if (!rmap_is_instruction_increment_address(request->instruction)) {
        printf("Rejecting unsupported non-incrementing write request\n");
        return RMAP_STATUS_FIELD_CODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED;
    }

    /* Incrementing. */

    assert(
        start_address + request->data_length >= start_address &&
        "Unexpected wrap");
    const uint64_t end_address = start_address + request->data_length;
    if (end_address > custom_context->target_memory_start_address +
            custom_context->target_memory_size) {
        printf("Rejecting write request due to end outside target memory\n");
        return RMAP_STATUS_FIELD_CODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED;
    }

    const size_t offset =
        start_address - custom_context->target_memory_start_address;
    memcpy(custom_context->target_memory + offset, data, request->data_length);

    printf(
        "Wrote data to address 0x%08" PRIX64 " with size %" PRIu32 ":\n",
        start_address,
        request->data_length);
    print_data(data, request->data_length);

    return RMAP_STATUS_FIELD_CODE_SUCCESS;
}

static enum rmap_status_field_code read_request(
    struct rmap_node *const node,
    void *const transaction_custom_context,
    void **const data,
    size_t *const data_size,
    const struct rmap_node_target_request *const request)
{
    (void)transaction_custom_context;

    printf("Processing read request\n");
    struct custom_context *const custom_context = node->custom_context;

    if (request->key != custom_context->target_key) {
        printf("Rejecting read request due to invalid key\n");
        return RMAP_STATUS_FIELD_CODE_INVALID_KEY;
    }

    if (request->target_logical_address !=
        custom_context->target_logical_address) {
        printf("Rejecting read request due to invalid logical address\n");
        return RMAP_STATUS_FIELD_CODE_INVALID_TARGET_LOGICAL_ADDRESS;
    }

    /* This implementation reads bytewise and has no alignment requirements. */

    const uint64_t start_address =
        (uint64_t)request->extended_address << 32 | request->address;

    if (start_address < custom_context->target_memory_start_address ||
        start_address > custom_context->target_memory_start_address +
                custom_context->target_memory_size - 1) {
        printf("Rejecting read request due to address outside target memory\n");
        return RMAP_STATUS_FIELD_CODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED;
    }

    if (!rmap_is_instruction_increment_address(request->instruction)) {
        printf("Rejecting unsupported non-incrementing read request\n");
        return RMAP_STATUS_FIELD_CODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED;
    }

    /* Incrementing. */

    assert(
        start_address + request->data_length >= start_address &&
        "Unexpected wrap");
    const uint64_t end_address = start_address + request->data_length;
    if (end_address > custom_context->target_memory_start_address +
            custom_context->target_memory_size) {
        printf("Rejecting read request due to end outside target memory\n");
        return RMAP_STATUS_FIELD_CODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED;
    }

    const size_t offset =
        start_address - custom_context->target_memory_start_address;
    memcpy(*data, custom_context->target_memory + offset, request->data_length);
    *data_size = request->data_length;

    return RMAP_STATUS_FIELD_CODE_SUCCESS;
}

static enum rmap_status_field_code rmw_request(
    struct rmap_node *const node,
    void *const transaction_custom_context,
    void **const read_data,
    size_t *const read_data_size,
    const struct rmap_node_target_request *const request,
    const void *const data)
{
    (void)transaction_custom_context;

    printf("Processing RMW request\n");
    struct custom_context *const custom_context = node->custom_context;

    if (request->key != custom_context->target_key) {
        printf("Rejecting RMW request due to invalid key\n");
        return RMAP_STATUS_FIELD_CODE_INVALID_KEY;
    }

    if (request->target_logical_address !=
        custom_context->target_logical_address) {
        printf("Rejecting RMW request due to invalid logical address\n");
        return RMAP_STATUS_FIELD_CODE_INVALID_TARGET_LOGICAL_ADDRESS;
    }

    /* This implementation writes bytewise and has no alignment requirements. */

    const uint64_t start_address =
        (uint64_t)request->extended_address << 32 | request->address;

    if (start_address < custom_context->target_memory_start_address ||
        start_address > custom_context->target_memory_start_address +
                custom_context->target_memory_size - 1) {
        printf("Rejecting RMW request due to address outside target memory\n");
        return RMAP_STATUS_FIELD_CODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED;
    }

    assert(
        start_address + request->data_length >= start_address &&
        "Unexpected wrap");
    const uint64_t end_address = start_address + request->data_length;
    if (end_address > custom_context->target_memory_start_address +
            custom_context->target_memory_size) {
        printf("Rejecting RMW request due to end outside target memory\n");
        return RMAP_STATUS_FIELD_CODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED;
    }

    /* This implementation uses bitwise (mask AND data) OR ((NOT mask) AND read)
     * to form the write data (similar to the example in the RMAP standard).
     *
     * This means bits set in the mask will be taken from the command data and
     * bits cleared in the mask will be taken from the read data.
     *
     * For example replacing bits 0-3:
     * - Command data: 0x01
     * - Read data: 0x22
     * - Mask: 0x0F
     * - Written data: 0x21
     *
     * For example clearing bits 2-5:
     * - Command data: 0x00
     * - Read data: 0xFF
     * - Mask: 0x3C
     * - Written data: 0xC3
     */
    const size_t offset =
        start_address - custom_context->target_memory_start_address;
    *read_data_size = request->data_length / 2;
    memcpy(*read_data, custom_context->target_memory + offset, *read_data_size);
    const unsigned char *const data_bytes = data;
    const unsigned char *const read_data_bytes = *read_data;
    const unsigned char *const mask = data_bytes + *read_data_size;
    for (size_t i = 0; i < *read_data_size; ++i) {
        const uint8_t write_data =
            (mask[i] & data_bytes[i]) | (~mask[i] & read_data_bytes[i]);
        custom_context->target_memory[offset + i] = write_data;
    }

    printf(
        "Wrote data to address 0x%08" PRIX64 " with size %zu:\n",
        start_address,
        *read_data_size);
    print_data(custom_context->target_memory + offset, *read_data_size);

    return RMAP_STATUS_FIELD_CODE_SUCCESS;
}

int main(void)
{
    static struct custom_context custom_context;
    custom_context.target_memory = calloc(128, 1);
    custom_context.target_memory_start_address = 0x100;
    custom_context.target_memory_size = 128;
    custom_context.target_logical_address = 0xFE;
    custom_context.target_key = 0;

    struct rmap_node node;
    const struct rmap_node_callbacks callbacks = {
        .initiator =
            {
                .received_write_reply = NULL,
                .received_read_reply = NULL,
                .received_rmw_reply = NULL,
            },
        .target =
            {
                .allocate = allocate,
                .send_reply = send_reply,
                .write_request = write_request,
                .read_request = read_request,
                .rmw_request = rmw_request,
            },
    };
    const struct rmap_node_initialize_flags flags = {
        .is_target = 1,
        .is_initiator = 0,
        .is_reply_for_unused_packet_type_enabled = 1,
    };
    rmap_node_initialize(&node, &custom_context, &callbacks, flags);

    void *const transaction_custom_context = NULL;

    const bool has_eep_termination = false;

    enum rmap_status rmap_status;
    uint8_t buf[RMAP_COMMAND_HEADER_STATIC_SIZE + 32];
    size_t header_size;
    size_t packet_size;
    uint16_t transaction_identifier = 0;
    const uint8_t reply_address[] = {0x01, 0x02, 0x03};
    const uint8_t write_data[] = {
        0x00,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,
        0x99,
        0xAA,
        0xBB,
        0xCC,
        0xDD,
        0xEE,
        0xFF,
    };

    /* Read whole target memory. */
    rmap_status = rmap_initialize_header(
        buf,
        sizeof(buf),
        RMAP_PACKET_TYPE_COMMAND,
        RMAP_COMMAND_CODE_REPLY | RMAP_COMMAND_CODE_INCREMENT,
        sizeof(reply_address));
    if (rmap_status != RMAP_OK) {
        printf(
            "Failed to initialize header: %s\n",
            rmap_status_text(rmap_status));
        exit(EXIT_FAILURE);
    }
    rmap_set_target_logical_address(buf, 0xFE);
    rmap_set_key(buf, 0x00);
    rmap_set_reply_address(buf, reply_address, sizeof(reply_address));
    rmap_set_initiator_logical_address(buf, 0x67);
    rmap_set_transaction_identifier(buf, transaction_identifier++);
    rmap_set_extended_address(buf, 0x00);
    rmap_set_address(buf, custom_context.target_memory_start_address);
    rmap_set_data_length(buf, custom_context.target_memory_size);
    rmap_calculate_and_set_header_crc(buf);
    packet_size = rmap_calculate_header_size(buf);
    rmap_status = rmap_node_handle_incoming(
        &node,
        transaction_custom_context,
        buf,
        packet_size,
        has_eep_termination);
    printf("Node status: %s\n", rmap_status_text(rmap_status));

    /* Write to a subset of target memory. */
    rmap_status = rmap_initialize_header(
        buf,
        sizeof(buf),
        RMAP_PACKET_TYPE_COMMAND,
        RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY |
            RMAP_COMMAND_CODE_INCREMENT,
        sizeof(reply_address));
    if (rmap_status != RMAP_OK) {
        printf(
            "Failed to initialize header: %s\n",
            rmap_status_text(rmap_status));
        exit(EXIT_FAILURE);
    }
    rmap_set_target_logical_address(buf, 0xFE);
    rmap_set_key(buf, 0x00);
    rmap_set_reply_address(buf, reply_address, sizeof(reply_address));
    rmap_set_initiator_logical_address(buf, 0x67);
    rmap_set_transaction_identifier(buf, transaction_identifier++);
    rmap_set_extended_address(buf, 0x00);
    rmap_set_address(buf, 0x00000110);
    rmap_set_data_length(buf, sizeof(write_data));
    rmap_calculate_and_set_header_crc(buf);
    header_size = rmap_calculate_header_size(buf);
    memcpy(buf + header_size, write_data, sizeof(write_data));
    buf[header_size + sizeof(write_data)] =
        rmap_crc_calculate(buf + header_size, sizeof(write_data));
    packet_size = header_size + sizeof(write_data) + 1;
    rmap_status = rmap_node_handle_incoming(
        &node,
        transaction_custom_context,
        buf,
        packet_size,
        has_eep_termination);
    printf("Node status: %s\n", rmap_status_text(rmap_status));

    /* Read whole target memory. */
    rmap_status = rmap_initialize_header(
        buf,
        sizeof(buf),
        RMAP_PACKET_TYPE_COMMAND,
        RMAP_COMMAND_CODE_REPLY | RMAP_COMMAND_CODE_INCREMENT,
        sizeof(reply_address));
    if (rmap_status != RMAP_OK) {
        printf(
            "Failed to initialize header: %s\n",
            rmap_status_text(rmap_status));
        exit(EXIT_FAILURE);
    }
    rmap_set_target_logical_address(buf, 0xFE);
    rmap_set_key(buf, 0x00);
    rmap_set_reply_address(buf, reply_address, sizeof(reply_address));
    rmap_set_initiator_logical_address(buf, 0x67);
    rmap_set_transaction_identifier(buf, transaction_identifier++);
    rmap_set_extended_address(buf, 0x00);
    rmap_set_address(buf, custom_context.target_memory_start_address);
    rmap_set_data_length(buf, custom_context.target_memory_size);
    rmap_calculate_and_set_header_crc(buf);
    packet_size = rmap_calculate_header_size(buf);
    rmap_status = rmap_node_handle_incoming(
        &node,
        transaction_custom_context,
        buf,
        packet_size,
        has_eep_termination);
    printf("Node status: %s\n", rmap_status_text(rmap_status));

    /* Write with invalid logical address. */
    rmap_status = rmap_initialize_header(
        buf,
        sizeof(buf),
        RMAP_PACKET_TYPE_COMMAND,
        RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY |
            RMAP_COMMAND_CODE_INCREMENT,
        sizeof(reply_address));
    if (rmap_status != RMAP_OK) {
        printf(
            "Failed to initialize header: %s\n",
            rmap_status_text(rmap_status));
        exit(EXIT_FAILURE);
    }
    rmap_set_target_logical_address(buf, 0xAA);
    rmap_set_key(buf, 0x00);
    rmap_set_reply_address(buf, reply_address, sizeof(reply_address));
    rmap_set_initiator_logical_address(buf, 0x67);
    rmap_set_transaction_identifier(buf, transaction_identifier++);
    rmap_set_extended_address(buf, 0x00);
    rmap_set_address(buf, custom_context.target_memory_start_address);
    rmap_set_data_length(buf, sizeof(write_data));
    rmap_calculate_and_set_header_crc(buf);
    header_size = rmap_calculate_header_size(buf);
    memcpy(buf + header_size, write_data, sizeof(write_data));
    buf[header_size + sizeof(write_data)] =
        rmap_crc_calculate(buf + header_size, sizeof(write_data));
    packet_size = header_size + sizeof(write_data) + 1;
    rmap_status = rmap_node_handle_incoming(
        &node,
        transaction_custom_context,
        buf,
        packet_size,
        has_eep_termination);
    printf("Node status: %s\n", rmap_status_text(rmap_status));

    /* Write with invalid address before target memory. */
    rmap_status = rmap_initialize_header(
        buf,
        sizeof(buf),
        RMAP_PACKET_TYPE_COMMAND,
        RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY |
            RMAP_COMMAND_CODE_INCREMENT,
        sizeof(reply_address));
    if (rmap_status != RMAP_OK) {
        printf(
            "Failed to initialize header: %s\n",
            rmap_status_text(rmap_status));
        exit(EXIT_FAILURE);
    }
    rmap_set_target_logical_address(buf, 0xFE);
    rmap_set_key(buf, 0x00);
    rmap_set_reply_address(buf, reply_address, sizeof(reply_address));
    rmap_set_initiator_logical_address(buf, 0x67);
    rmap_set_transaction_identifier(buf, transaction_identifier++);
    rmap_set_extended_address(buf, 0x00);
    rmap_set_address(buf, custom_context.target_memory_start_address - 1);
    rmap_set_data_length(buf, sizeof(write_data));
    rmap_calculate_and_set_header_crc(buf);
    header_size = rmap_calculate_header_size(buf);
    memcpy(buf + header_size, write_data, sizeof(write_data));
    buf[header_size + sizeof(write_data)] =
        rmap_crc_calculate(buf + header_size, sizeof(write_data));
    packet_size = header_size + sizeof(write_data) + 1;
    rmap_status = rmap_node_handle_incoming(
        &node,
        transaction_custom_context,
        buf,
        packet_size,
        has_eep_termination);
    printf("Node status: %s\n", rmap_status_text(rmap_status));

    /* Write with invalid address and size moving past target memory end. */
    rmap_status = rmap_initialize_header(
        buf,
        sizeof(buf),
        RMAP_PACKET_TYPE_COMMAND,
        RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY |
            RMAP_COMMAND_CODE_INCREMENT,
        sizeof(reply_address));
    if (rmap_status != RMAP_OK) {
        printf(
            "Failed to initialize header: %s\n",
            rmap_status_text(rmap_status));
        exit(EXIT_FAILURE);
    }
    rmap_set_target_logical_address(buf, 0xFE);
    rmap_set_key(buf, 0x00);
    rmap_set_reply_address(buf, reply_address, sizeof(reply_address));
    rmap_set_initiator_logical_address(buf, 0x67);
    rmap_set_transaction_identifier(buf, transaction_identifier++);
    rmap_set_extended_address(buf, 0x00);
    rmap_set_address(
        buf,
        custom_context.target_memory_start_address +
            custom_context.target_memory_size - sizeof(write_data) + 1);
    rmap_set_data_length(buf, sizeof(write_data));
    rmap_calculate_and_set_header_crc(buf);
    header_size = rmap_calculate_header_size(buf);
    memcpy(buf + header_size, write_data, sizeof(write_data));
    buf[header_size + sizeof(write_data)] =
        rmap_crc_calculate(buf + header_size, sizeof(write_data));
    packet_size = header_size + sizeof(write_data) + 1;
    rmap_status = rmap_node_handle_incoming(
        &node,
        transaction_custom_context,
        buf,
        packet_size,
        has_eep_termination);
    printf("Node status: %s\n", rmap_status_text(rmap_status));

    /* Write with address and size reaching target memory end. */
    rmap_status = rmap_initialize_header(
        buf,
        sizeof(buf),
        RMAP_PACKET_TYPE_COMMAND,
        RMAP_COMMAND_CODE_WRITE | RMAP_COMMAND_CODE_REPLY |
            RMAP_COMMAND_CODE_INCREMENT,
        sizeof(reply_address));
    if (rmap_status != RMAP_OK) {
        printf(
            "Failed to initialize header: %s\n",
            rmap_status_text(rmap_status));
        exit(EXIT_FAILURE);
    }
    rmap_set_target_logical_address(buf, 0xFE);
    rmap_set_key(buf, 0x00);
    rmap_set_reply_address(buf, reply_address, sizeof(reply_address));
    rmap_set_initiator_logical_address(buf, 0x67);
    rmap_set_transaction_identifier(buf, transaction_identifier++);
    rmap_set_extended_address(buf, 0x00);
    rmap_set_address(
        buf,
        custom_context.target_memory_start_address +
            custom_context.target_memory_size - sizeof(write_data));
    rmap_set_data_length(buf, sizeof(write_data));
    rmap_calculate_and_set_header_crc(buf);
    header_size = rmap_calculate_header_size(buf);
    memcpy(buf + header_size, write_data, sizeof(write_data));
    buf[header_size + sizeof(write_data)] =
        rmap_crc_calculate(buf + header_size, sizeof(write_data));
    packet_size = header_size + sizeof(write_data) + 1;
    rmap_status = rmap_node_handle_incoming(
        &node,
        transaction_custom_context,
        buf,
        packet_size,
        has_eep_termination);
    printf("Node status: %s\n", rmap_status_text(rmap_status));

    /* Read whole target memory. */
    rmap_status = rmap_initialize_header(
        buf,
        sizeof(buf),
        RMAP_PACKET_TYPE_COMMAND,
        RMAP_COMMAND_CODE_REPLY | RMAP_COMMAND_CODE_INCREMENT,
        sizeof(reply_address));
    if (rmap_status != RMAP_OK) {
        printf(
            "Failed to initialize header: %s\n",
            rmap_status_text(rmap_status));
        exit(EXIT_FAILURE);
    }
    rmap_set_target_logical_address(buf, 0xFE);
    rmap_set_key(buf, 0x00);
    rmap_set_reply_address(buf, reply_address, sizeof(reply_address));
    rmap_set_initiator_logical_address(buf, 0x67);
    rmap_set_transaction_identifier(buf, transaction_identifier++);
    rmap_set_extended_address(buf, 0x00);
    rmap_set_address(buf, custom_context.target_memory_start_address);
    rmap_set_data_length(buf, custom_context.target_memory_size);
    rmap_calculate_and_set_header_crc(buf);
    packet_size = rmap_calculate_header_size(buf);
    rmap_status = rmap_node_handle_incoming(
        &node,
        transaction_custom_context,
        buf,
        packet_size,
        has_eep_termination);
    printf("Node status: %s\n", rmap_status_text(rmap_status));

    /* RMW. */
    rmap_status = rmap_initialize_header(
        buf,
        sizeof(buf),
        RMAP_PACKET_TYPE_COMMAND,
        RMAP_COMMAND_CODE_RMW,
        sizeof(reply_address));
    if (rmap_status != RMAP_OK) {
        printf(
            "Failed to initialize header: %s\n",
            rmap_status_text(rmap_status));
        exit(EXIT_FAILURE);
    }
    rmap_set_target_logical_address(buf, 0xFE);
    rmap_set_key(buf, 0x00);
    rmap_set_reply_address(buf, reply_address, sizeof(reply_address));
    rmap_set_initiator_logical_address(buf, 0x67);
    rmap_set_transaction_identifier(buf, transaction_identifier++);
    rmap_set_extended_address(buf, 0x00);
    rmap_set_address(buf, 0x00000110);
    const uint8_t rmw_data_and_mask[] = {
        0x0F,
        0xF0,
        0x0F,
        0xF0,
        0x0F,
        0xF0,
        0x0F,
        0xF0,
    };
    rmap_set_data_length(buf, sizeof(rmw_data_and_mask));
    rmap_calculate_and_set_header_crc(buf);
    header_size = rmap_calculate_header_size(buf);
    memcpy(buf + header_size, rmw_data_and_mask, sizeof(rmw_data_and_mask));
    buf[header_size + sizeof(rmw_data_and_mask)] =
        rmap_crc_calculate(buf + header_size, sizeof(rmw_data_and_mask));
    packet_size = header_size + sizeof(rmw_data_and_mask) + 1;
    rmap_status = rmap_node_handle_incoming(
        &node,
        transaction_custom_context,
        buf,
        packet_size,
        has_eep_termination);
    printf("Node status: %s\n", rmap_status_text(rmap_status));

    /* Read whole target memory. */
    rmap_status = rmap_initialize_header(
        buf,
        sizeof(buf),
        RMAP_PACKET_TYPE_COMMAND,
        RMAP_COMMAND_CODE_REPLY | RMAP_COMMAND_CODE_INCREMENT,
        sizeof(reply_address));
    if (rmap_status != RMAP_OK) {
        printf(
            "Failed to initialize header: %s\n",
            rmap_status_text(rmap_status));
        exit(EXIT_FAILURE);
    }
    rmap_set_target_logical_address(buf, 0xFE);
    rmap_set_key(buf, 0x00);
    rmap_set_reply_address(buf, reply_address, sizeof(reply_address));
    rmap_set_initiator_logical_address(buf, 0x67);
    rmap_set_transaction_identifier(buf, transaction_identifier++);
    rmap_set_extended_address(buf, 0x00);
    rmap_set_address(buf, custom_context.target_memory_start_address);
    rmap_set_data_length(buf, custom_context.target_memory_size);
    rmap_calculate_and_set_header_crc(buf);
    packet_size = rmap_calculate_header_size(buf);
    rmap_status = rmap_node_handle_incoming(
        &node,
        transaction_custom_context,
        buf,
        packet_size,
        has_eep_termination);
    printf("Node status: %s\n", rmap_status_text(rmap_status));
}
