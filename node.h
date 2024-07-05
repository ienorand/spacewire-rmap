#ifndef NODE_H
#define NODE_H

#include "rmap.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rmap_node_initialize_flags {
    unsigned int is_target : 1;
    unsigned int is_initiator : 1;
    unsigned int is_reply_for_unused_packet_type_enabled : 1;
};

/* Forward declaration needed for callback signatures. */
struct rmap_node_context;

/* Information for combined authorization and memory access callbacks. */
struct rmap_node_target_request {
    uint8_t target_logical_address;
    uint8_t instruction;
    uint8_t key;
    uint8_t initiator_logical_address;
    uint16_t transaction_identifier;
    uint8_t extended_address;
    uint32_t address;
    uint32_t data_length;
};

/* TODO:
 * Should allocation failure be returned as a status from the
 * rmap_node_handle_incoming() function instead?
 *
 * By extension, should all error information be reported as return values from
 * rmap_node_handle_incoming() instead of being part of the node error
 * information? In the current interface it is probably expected that the
 * caller will chack the error information after each call to
 * rmap_node_handle_incoming() anyway, so having it separated is questionable.
 */
/* Callback for allocating memory for reply packets.
 *
 * Allocation failure can be indicated by returning NULL.
 */
typedef void *(*rmap_node_target_allocate_callback)(
    struct rmap_node_context *context,
    size_t size);

/* Callback for sending replies.
 *
 * Data in @p packet will have been allocated via
 * rmap_node_target_allocate_callback(), ownership of this allocation is
 * transferred from the caller to the callee. This library will not handle its
 * deallocation.
 */
typedef void (*rmap_node_target_send_reply_callback)(
    struct rmap_node_context *context,
    void *packet,
    size_t size);

/* Callback for both authorizing and performing a write.
 *
 * Return value of implemented callback must be one of:
 * * RMAP_STATUS_FIELD_CODE_INVALID_KEY
 * * RMAP_STATUS_FIELD_CODE_INVALID_TARGET_LOGICAL_ADDRESS
 * * RMAP_STATUS_FIELD_CODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED
 * * RMAP_STATUS_FIELD_CODE_GENERAL_ERROR_CODE
 * * RMAP_STATUS_FIELD_CODE_SUCCESS
 * */
typedef enum rmap_status_field_code (*rmap_node_target_write_request_callback)(
    struct rmap_node_context *context,
    const struct rmap_node_target_request *request,
    const void *data);

/* Callback for both authorizing and performing a read.
 *
 * Return value of implemented callback must be one of:
 * * RMAP_STATUS_FIELD_CODE_INVALID_KEY
 * * RMAP_STATUS_FIELD_CODE_INVALID_TARGET_LOGICAL_ADDRESS
 * * RMAP_STATUS_FIELD_CODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED
 * * RMAP_STATUS_FIELD_CODE_GENERAL_ERROR_CODE (implies short read)
 * * RMAP_STATUS_FIELD_CODE_SUCCESS
 * */
typedef enum rmap_status_field_code (*rmap_node_target_read_request_callback)(
    struct rmap_node_context *context,
    void *data,
    size_t *data_size,
    const struct rmap_node_target_request *request);

/* Callback for both authorizing and performing a RMW.
 *
 * Return value of implemented callback must be one of:
 * * RMAP_STATUS_FIELD_CODE_INVALID_KEY
 * * RMAP_STATUS_FIELD_CODE_INVALID_TARGET_LOGICAL_ADDRESS
 * * RMAP_STATUS_FIELD_CODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED
 * * RMAP_STATUS_FIELD_CODE_GENERAL_ERROR_CODE (implies short read or failed
 *   write)
 * * RMAP_STATUS_FIELD_CODE_SUCCESS
 * */
typedef enum rmap_status_field_code (*rmap_node_target_rmw_request_callback)(
    struct rmap_node_context *context,
    void *read_data,
    size_t *read_data_size,
    const struct rmap_node_target_request *request,
    const void *data);

typedef void (*rmap_node_initiator_received_write_reply_callback)(
    struct rmap_node_context *context,
    uint16_t transaction_identifier,
    enum rmap_status_field_code status);

typedef void (*rmap_node_initiator_received_read_reply_callback)(
    struct rmap_node_context *context,
    uint16_t transaction_identifier,
    enum rmap_status_field_code status,
    const void *data,
    size_t data_length);

typedef void (*rmap_node_initiator_received_rmw_reply_callback)(
    struct rmap_node_context *context,
    uint16_t transaction_identifier,
    enum rmap_status_field_code status,
    const void *data,
    size_t data_length);

struct rmap_node_initiator_callbacks {
    rmap_node_initiator_received_write_reply_callback received_write_reply;
    rmap_node_initiator_received_read_reply_callback received_read_reply;
    rmap_node_initiator_received_rmw_reply_callback received_rmw_reply;
};

struct rmap_node_target_callbacks {
    rmap_node_target_allocate_callback allocate;
    rmap_node_target_send_reply_callback send_reply;
    rmap_node_target_write_request_callback write_request;
    rmap_node_target_read_request_callback read_request;
    rmap_node_target_rmw_request_callback rmw_request;
};

struct rmap_node_callbacks {
    struct rmap_node_target_callbacks target;
    struct rmap_node_initiator_callbacks initiator;
};

struct rmap_node_target_context {
    struct rmap_node_target_callbacks callbacks;
    unsigned int is_reply_for_unused_packet_type_enabled : 1;
};

struct rmap_node_initiator_context {
    struct rmap_node_initiator_callbacks callbacks;
};

struct rmap_node_context {
    void *custom_context;
    struct rmap_node_callbacks callbacks;
    unsigned int is_target : 1;
    unsigned int is_initiator : 1;
    unsigned int is_reply_for_unused_packet_type_enabled : 1;
};

enum rmap_status rmap_node_initialize(
    struct rmap_node_context *context,
    void *custom_context,
    const struct rmap_node_callbacks *callbacks,
    struct rmap_node_initialize_flags flags);

enum rmap_status rmap_node_handle_incoming(
    struct rmap_node_context *context,
    const void *packet,
    size_t size);

#ifdef __cplusplus
}
#endif

#endif /* NODE_H */
