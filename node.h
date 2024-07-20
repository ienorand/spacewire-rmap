#ifndef NODE_H
#define NODE_H

/** Target and initiator node for incoming SpaceWire RMAP packets.
 *
 * @file
 */

#include "rmap.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Flags for configuring the persistent behaviour of a node at initialization.
 */
struct rmap_node_initialize_flags {
    /** Flag indicating if the node should accept incoming commands. */
    unsigned int is_target : 1;
    /** Flag indicating if the node should accept incoming replies. */
    unsigned int is_initiator : 1;
    /** Flag indicating if the node should send a reply for incoming commands
     *  with an unused (reserved) packet type.
     *
     * This behaviour is optional according to the RMAP standard
     * (ECSS-E-ST-50-52C sections 5.3.3.4.6-c, 5.4.3.4.6-c, and 5.5.3.4.6-c).
     */
    unsigned int is_reply_for_unused_packet_type_enabled : 1;
};

/* Forward declaration needed for callback signatures. */
struct rmap_node_context;

/** Generic request parameters for combined authorization and memory access
 *  callbacks.
 */
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

/** Callback for allocating memory for a reply packet.
 *
 * This callback will be invoked when memory is to be allocated for a reply in
 * a target node.
 *
 * Access to the custom user context is available via the node context object.
 *
 * This callback is expected to allocate memory with a size greater than or
 * equal to @p size, and to return a pointer to this memory.
 *
 * Allocation failure must be indicated by returning a NULL pointer.
 *
 * This callback temporarily transfers ownership of the allocation from the
 * user to the node, it will later be returned via the send reply callback.
 *
 * @param[in,out] context Node context object.
 * @param size Number of bytes to allocate.
 *
 * @return Pointer to allocated memory or NULL on allocation failure.
 */
typedef void *(*rmap_node_target_allocate_callback)(
    struct rmap_node_context *context,
    size_t size);

/** Callback for sending a reply.
 *
 * This callback will be invoked when a reply is to be sent by a target node.
 *
 * Access to the custom user context is available via the node context object.
 *
 * This callback is expected to send the data given by @p packet and @p size as
 * a spacewire packet.
 *
 * Send failure can be indicated by returning RMAP_NODE_SEND_REPLY_FAILURE,
 * this value will then be returned by the rmap_node_handle_incoming() call
 * which triggered this callback.
 *
 * The callback is expected to return RMAP_OK on success or if send failure is
 * not indicated.
 *
 * The data in @p packet will have been allocated via
 * rmap_node_target_allocate_callback(); this callback transfers the ownership
 * of this allocation to the user which must handle its deallocation.
 *
 * @param[in,out] context Node context object.
 * @param[in] packet RMAP packet data to be sent.
 * @param size Number of bytes to be sent from @p packet.
 *
 * @retval RMAP_NODE_SEND_REPLY_FAILURE Send failure.
 * @retval RMAP_OK Send success.
 */
typedef enum rmap_status (*rmap_node_target_send_reply_callback)(
    struct rmap_node_context *context,
    void *packet,
    size_t size);

/** Callback for both authorizing and performing a write.
 *
 * This callback will be invoked when a write command has been received by a
 * target node.
 *
 * Access to the custom user context is available via the node context object.
 *
 * This callback is expected to first perform authorization of the generic
 * request parameters (@p request).
 *
 * Authorization failure must be indicated by returning one of:
 * * RMAP_STATUS_FIELD_CODE_INVALID_KEY.
 * * RMAP_STATUS_FIELD_CODE_INVALID_TARGET_LOGICAL_ADDRESS.
 * * RMAP_STATUS_FIELD_CODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED.
 *
 * RMAP_STATUS_FIELD_CODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED should be
 * used to indicate rejection for "any other reason".
 *
 * The callback is expected to then perform the write using the data in
 * @p data.
 *
 * Write failure must be indicated by returning
 * RMAP_STATUS_FIELD_CODE_GENERAL_ERROR_CODE.
 *
 * The callback is finally expected to notify the user that a write operation
 * has occurred and to then return RMAP_STATUS_FIELD_CODE_SUCCESS.
 *
 * A write reply will be sent based on the return value if the write command
 * was with-reply.
 *
 * @attention The callback @e must return one of the return values defined for
 *            this callback.
 *
 * @param[in,out] context Node context object.
 * @param[in] request Generic request parameters.
 * @param[in] data Data to be written.
 *
 * @retval RMAP_STATUS_FIELD_CODE_INVALID_KEY Command rejected due to invalid
 *         key.
 * @retval RMAP_STATUS_FIELD_CODE_INVALID_TARGET_LOGICAL_ADDRESS Command
 *         rejected due to invalid target logical address.
 * @retval RMAP_STATUS_FIELD_CODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED
 *         Command rejected for any other reason.
 * @retval RMAP_STATUS_FIELD_CODE_GENERAL_ERROR_CODE Write memory access
 *         failure.
 * @retval RMAP_STATUS_FIELD_CODE_SUCCESS Write operation successful.
 */
typedef enum rmap_status_field_code (*rmap_node_target_write_request_callback)(
    struct rmap_node_context *context,
    const struct rmap_node_target_request *request,
    const void *data);

/** Callback for both authorizing and performing a read.
 *
 * This callback will be invoked when a read command has been received by an
 * initiator node.
 *
 * Access to the custom user context is available via the node context object.
 *
 * This callback is expected to first perform authorization of the generic
 * request parameters (@p request).
 *
 * Authorization failure must be indicated by returning one of:
 * * RMAP_STATUS_FIELD_CODE_INVALID_KEY.
 * * RMAP_STATUS_FIELD_CODE_INVALID_TARGET_LOGICAL_ADDRESS.
 * * RMAP_STATUS_FIELD_CODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED.
 *
 * RMAP_STATUS_FIELD_CODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED should be
 * used to indicate rejection for "any other reason".
 *
 * The callback is expected to then perform the read, storing the read data in
 * @p data and storing its size in @p data_size.
 *
 * Read failure must be indicated by setting @p data_size to a value that is
 * less than the requested data length.
 *
 * The callback is finally expected to notify the user that a read operation
 * has occurred and to then return RMAP_STATUS_FIELD_CODE_SUCCESS.
 *
 * A read reply will be sent based on the return value and the read data.
 *
 * @attention The callback @e must return one of the return values defined for
 *            this callback.
 *
 * @param[in,out] context Node context object.
 * @param[out] data Destination for read data.
 * @param[out] data_size Number of bytes stored into @p data.
 * @param[in] request Generic request parameters.
 *
 * @retval RMAP_STATUS_FIELD_CODE_INVALID_KEY Command rejected due to invalid
 *         key.
 * @retval RMAP_STATUS_FIELD_CODE_INVALID_TARGET_LOGICAL_ADDRESS Command
 *         rejected due to invalid target logical address.
 * @retval RMAP_STATUS_FIELD_CODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED
 *         Command rejected for any other reason.
 * @retval RMAP_STATUS_FIELD_CODE_SUCCESS Command accepted and read operation
 *         was performed. Failure in read memory access is independently
 *         indicated by setting @p data_size to a value less than the requested
 *         data length.
 */
typedef enum rmap_status_field_code (*rmap_node_target_read_request_callback)(
    struct rmap_node_context *context,
    void *data,
    size_t *data_size,
    const struct rmap_node_target_request *request);

/** Callback for both authorizing and performing a RMW.
 *
 * This callback will be invoked when a RMW command has been received by a
 * target node.
 *
 * Access to the custom user context is available via the node context object.
 *
 * This callback is expected to first perform authorization of the generic
 * request parameters (@p request).
 *
 * Authorization failure must be indicated by returning one of:
 * * RMAP_STATUS_FIELD_CODE_INVALID_KEY.
 * * RMAP_STATUS_FIELD_CODE_INVALID_TARGET_LOGICAL_ADDRESS.
 * * RMAP_STATUS_FIELD_CODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED.
 *
 * RMAP_STATUS_FIELD_CODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED should be
 * used to indicate rejection for "any other reason".
 *
 * The callback is expected to then perform the read part of the RMW.
 *
 * The read data should be stored in @p read_data.
 *
 * Read failure must be indicated by setting @p read_data_size to a value that
 * is less than the requested data length and by returning
 * RMAP_STATUS_FIELD_CODE_SUCCESS.
 *
 * The callback is expected to then perform the write part of the RMW.
 *
 * The write data shall be calculated based on the read data, data (first half
 * of @p data), and data mask (second half of @p data). The way in which the
 * write data is calculated is not specified by the RMAP standard and must by
 * defined by the user.
 *
 * Write failure can be indicated by returning
 * RMAP_STATUS_FIELD_CODE_GENERAL_ERROR_CODE (a deviation from the RMAP
 * standard) or can be silently ignored (according to the RMAP standard).
 *
 * The callback is finally expected to notify the user that a RMW operation has
 * occurred and to then return RMAP_STATUS_FIELD_CODE_SUCCESS.
 *
 * A RMW reply will be sent based on the return value and the read data.
 *
 * @attention The callback @e must return one of the return values defined for
 *            this callback.
 *
 * @par Read and write failure details.
 * @parblock
 * The RMAP standard states the following about RMW write failures:
 *
 *   If the read or write operations to memory fails, the target shall either:
 *   1. Append an EEP to the end of the data sent in the reply to the
 *      initiator, or
 *   2. Append an appropriate data CRC byte covering the data sent in the reply
 *      to the initiator, followed by an EOP.
 *        NOTE In this case the data length field in the reply contains the
 *        amount of data requested which is different to the amount of data
 *        returned in the data field of the reply.
 *
 * (Notes are non-normative in ECSS standards.)
 *
 * This indicates that:
 * * It is expected that the sending of the RMW reply including the read data
 *   will start and potentially even finish before the write operation occurs.
 * * The status field is expected to not be possible to modify after the read
 *   operation has started.
 * * The only way to indicate a write failure would be to terminate the reply
 *   with an early EOP or an EEP, but there are no guarantees that this is
 *   possible since the reply may already have been sent by the time the write
 *   operation finishes.
 *
 * Since this library does not start sending the reply before the whole RMW
 * operation has completed, it does in practice have access to modify the
 * status field of the reply. It allows the user setting the status field by
 * returning RMAP_STATUS_FIELD_CODE_GENERAL_ERROR_CODE.
 *
 * This should only be used to indicate write failures; the method for
 * indication of read failures is already well-defined and functional based on
 * the RMAP standard.
 * @endparblock
 *
 * @param[in,out] context Node context object.
 * @param[out] read_data Destination for read data.
 * @param[out] read_data_size Number of bytes stored into @p read_data.
 * @param[in] request Generic request parameters.
 * @param[in] data Data field of command with first half containing data and
 *            the second half containing the data mask.
 *
 * @retval RMAP_STATUS_FIELD_CODE_INVALID_KEY Command rejected due to invalid
 *         key.
 * @retval RMAP_STATUS_FIELD_CODE_INVALID_TARGET_LOGICAL_ADDRESS Command
 *         rejected due to invalid target logical address.
 * @retval RMAP_STATUS_FIELD_CODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED
 *         Command rejected for any other reason.
 * @retval RMAP_STATUS_FIELD_CODE_SUCCESS Command accepted and RMW operation
 *         was performed. Failure in read part of RMW operation is
 *         independently indicated by setting @p read_data_size to a value less
 *         than the requested data length.
 * @retval RMAP_STATUS_FIELD_CODE_GENERAL_ERROR_CODE Failure in write part of
 *         RMW operation. (Deliberate deviation from RMAP standard).
 */
typedef enum rmap_status_field_code (*rmap_node_target_rmw_request_callback)(
    struct rmap_node_context *context,
    void *read_data,
    size_t *read_data_size,
    const struct rmap_node_target_request *request,
    const void *data);

/** Callback for a received write reply.
 *
 * This callback will be invoked when a write reply has been received by an
 * initiator node, indicating to the user of the node that a previously
 * initiated write action has completed.
 *
 * This callback is expected to forward the transaction identifier and status
 * to the user.
 *
 * Access to the custom user context is available via the node context object.
 *
 * @param[in,out] context Node context object.
 * @param transaction_identifier Transaction identifier of received reply.
 * @param status Status field code of reply.
 */
typedef void (*rmap_node_initiator_received_write_reply_callback)(
    struct rmap_node_context *context,
    uint16_t transaction_identifier,
    enum rmap_status_field_code status);

/** Callback for a received read reply.
 *
 * This callback will be invoked when a read reply has been received by an
 * initiator node, indicating to the user of the node that a previously
 * initiated read action has completed.
 *
 * The callback is expected to forward the transaction identifier, status, and
 * data to the user.
 *
 * Access to the custom user context is available via the node context object.
 *
 * @param[in,out] context Node context object.
 * @param transaction_identifier Transaction identifier of received reply.
 * @param status Status field code of reply.
 * @param[in] data Data field of reply.
 * @param data_length Number of bytes in @p data.
 */
typedef void (*rmap_node_initiator_received_read_reply_callback)(
    struct rmap_node_context *context,
    uint16_t transaction_identifier,
    enum rmap_status_field_code status,
    const void *data,
    size_t data_length);

/** Callback for a received RMW reply.
 *
 * This callback will be invoked when a RMW reply has been received by an
 * initiator node, indicating to the user of the node that a previously
 * initiated RMW action has completed.
 *
 * The callback is expected to forward the transaction identifier, status, and
 * data to the user.
 *
 * Access to the custom user context is available via the node context object.
 *
 * @param[in,out] context Node context object.
 * @param transaction_identifier Transaction identifier of received reply.
 * @param status Status field code of reply.
 * @param[in] data Data field of reply.
 * @param data_length Number of bytes in @p data.
 */
typedef void (*rmap_node_initiator_received_rmw_reply_callback)(
    struct rmap_node_context *context,
    uint16_t transaction_identifier,
    enum rmap_status_field_code status,
    const void *data,
    size_t data_length);

struct rmap_node_initiator_callbacks {
    /** Callback for a received write reply. */
    rmap_node_initiator_received_write_reply_callback received_write_reply;
    /** Callback for a received read reply. */
    rmap_node_initiator_received_read_reply_callback received_read_reply;
    /** Callback for a received RMW reply. */
    rmap_node_initiator_received_rmw_reply_callback received_rmw_reply;
};

struct rmap_node_target_callbacks {
    /** Callback for allocating memory for reply packets. */
    rmap_node_target_allocate_callback allocate;
    /** Callback for sending a reply. */
    rmap_node_target_send_reply_callback send_reply;
    /** Callback for both authorizing and performing a write. */
    rmap_node_target_write_request_callback write_request;
    /** Callback for both authorizing and performing a read. */
    rmap_node_target_read_request_callback read_request;
    /** Callback for both authorizing and performing a RMW. */
    rmap_node_target_rmw_request_callback rmw_request;
};

struct rmap_node_callbacks {
    struct rmap_node_target_callbacks target;
    struct rmap_node_initiator_callbacks initiator;
};

/** RMAP node context object. */
struct rmap_node_context {
    /** Custom user context available to callbacks. */
    void *custom_context;
    /** Callbacks registered in node. */
    struct rmap_node_callbacks callbacks;
    /** Flag indicating if the node accepts incoming commands. */
    unsigned int is_target : 1;
    /** Flag indicating if the node accepts incoming replies. */
    unsigned int is_initiator : 1;
    /** Flag indicating if the node will send a reply for incoming commands
     *  with an unused (reserved) packet type.
     *
     * This behaviour is optional according to the RMAP standard
     * (ECSS-E-ST-50-52C sections 5.3.3.4.6-c, 5.4.3.4.6-c, and 5.5.3.4.6-c).
     */
    unsigned int is_reply_for_unused_packet_type_enabled : 1;
};

/** Intialize an RMAP node.
 *
 * Initialize a context object for an RMAP node, such that it can then be used
 * to handle incoming RMAP packets via @p rmap_node_handle_incoming().
 *
 * The persistent behaviour of the node is configured via the @p flags
 * parameter.
 *
 * The node can be configured as a target, initiator, or both.
 *
 * @pre If the node is configured as a target, each target callback in
 *      @p callbacks must be a valid function pointer.
 *
 * @pre If the node is configured as an initiator, each initiator callback in
 *      @p callbacks must be a valid function pointer.
 *
 * @param[out] context Destination for initialized node context object.
 * @param[in] custom_context Custom user context available to callbacks of
 *            node.
 * @param[in] callbacks Callbacks to be registered in node.
 * @param flags Option flags for node behaviour.
 *
 * @retval RMAP_NODE_NO_TARGET_OR_INITIATOR Attempt to initialize node as
 *         neither target nor initiator.
 * @retval RMAP_OK Node intialized successfully.
 */
enum rmap_status rmap_node_initialize(
    struct rmap_node_context *context,
    void *custom_context,
    const struct rmap_node_callbacks *callbacks,
    struct rmap_node_initialize_flags flags);

/** Handle incoming spacewire packet to node.
 *
 * The incoming packet will be verified to be a valid RMAP packet and then
 * processed.
 *
 * The processing will normally results in one or more callbacks being invoked.
 *
 * Error information gathering by the node is indirectly supported via the
 * return value, most non-success return values corresponds to a node error
 * information status from the RMAP standard.
 *
 * @pre @p size must indicate the exact number of bytes in the incoming packet.
 *
 * @param[in,out] context Node context object.
 * @param[in] packet Incoming packet data.
 * @param size Number of bytes in incoming packet in @p packet.
 *
 * @retval RMAP_NO_RMAP_PROTOCOL Incoming packet discarded due to non-RMAP
 *         protocol.
 * @retval RMAP_INCOMPLETE_HEADER Incoming packet discarded due to not being
 *         large enough to contain the whole RMAP header.
 * @retval RMAP_HEADER_CRC_ERROR Incoming packet discarded due to header CRC
 *         indicating that errors are present in the header.
 * @retval RMAP_NODE_COMMAND_RECEIVED_BY_INITIATOR Incoming command packet
 *         discarded due to node being configured to reject incoming commands.
 * @retval RMAP_NODE_REPLY_RECEIVED_BY_TARGET Incoming reply packet
 *         discarded due to node being configured to reject incoming replies.
 * @retval RMAP_NODE_ALLOCATION_FAILURE Incoming packet and intended reply
 *         discarded due to allocation failure.
 * @retval RMAP_NODE_SEND_REPLY_FAILURE Incoming packet and intended reply
 *         discarded due to reply sending failure.
 * @retval RMAP_UNUSED_PACKET_TYPE Incoming packet rejected due to the packet
 *         type field having the reserved bit set. An error reply may have been
 *         sent, if applicable, depending on the configuration of the node.
 * @retval RMAP_UNUSED_COMMAND_CODE Incoming packet rejected due to the command
 *         field containing a reserved command code.
 * @retval RMAP_NODE_PACKET_ERROR Incoming reply packet rejected due to one of:
 *         * The packet type field having the reserved bit set.
 *         * The command field containing a reserved command code.
 *         * The command field not having the reply bit set.
 * @retval RMAP_NODE_INVALID_REPLY Incoming reply packet rejected due to one
 *         of:
 *         * The packet being a RMW reply with a data length field value that
 *           is invalid for a RMW reply.
 *         * The packet being smaller than indicated by the data length field.
 *         * The packet being larger than indicated by the data length field.
 *         * The data CRC indicating errors in the data.
 * @retval RMAP_INSUFFICIENT_DATA Incoming write or RMW command packet rejected
 *         due to being smaller than indicated by the data length. An error
 *         reply has been sent if applicable.
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
 *         been sent if applicable
 * @retval RMAP_NODE_INVALID_TARGET_LOGICAL_ADDRESS Incoming command packet
 *         rejected due to its target logical address not being authorized by
 *         the request callback. An error reply has been sent if applicable.
 * @retval RMAP_NODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED Incoming command
 *         packet rejected due to not being authorized for "any other reason"
 *         by the request callback. An error reply has been sent if applicable.
 *         by the command code.
 * @retval RMAP_NODE_MEMORY_ACCESS_ERROR Incoming write or RMW command rejected
 *         due to write memory access error. An error reply has been sent if
 *         applicable.
 */
enum rmap_status rmap_node_handle_incoming(
    struct rmap_node_context *context,
    const void *packet,
    size_t size);

#ifdef __cplusplus
}
#endif

#endif /* NODE_H */
