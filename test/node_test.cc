#include <gmock/gmock.h>
#include <gtest/gtest.h>

extern "C" {
#include "node.h"
}

/* RMAP test patterns from ECSS‐E‐ST‐50‐52C, 5 February 2010. */

static const uint8_t test_pattern0_unverified_incrementing_write_with_reply[] =
    {
        /* Target Logical Address */
        0xFE,
        /* Protocol Identifier */
        0x01,
        /* Instruction */
        0x6C,
        /* Key */
        0x00,
        /* Initiator Logical Address */
        0x67,
        /* Transaction Identifier MS */
        0x00,
        /* Transaction Identifier LS */
        0x00,
        /* Extended Address */
        0x00,
        /* Address MS */
        0xA0,
        /* Address */
        0x00,
        /* Address */
        0x00,
        /* Address LS */
        0x00,
        /* Data Length MS */
        0x00,
        /* Data Length */
        0x00,
        /* Data Length LS */
        0x10,
        /* Header CRC */
        0x9F,
        /* Data */
        0x01,
        0x23,
        0x45,
        0x67,
        0x89,
        0xAB,
        0xCD,
        0xEF,
        0x10,
        0x11,
        0x12,
        0x13,
        0x14,
        0x15,
        0x16,
        0x17,
        /* Data CRC */
        0x56};

static const uint8_t test_pattern0_expected_write_reply[] = {
    /* Initiator Logical Address */
    0x67,
    /* Protocol Identifier */
    0x01,
    /* Instruction */
    0x2C,
    /* Status */
    0x00,
    /* Target Logical Address */
    0xFE,
    /* Transaction Identifier MS */
    0x00,
    /* Transaction Identifier MS */
    0x00,
    /* Header CRC */
    0xED};

static const uint8_t test_pattern1_incrementing_read[] = {
    /* Target Logical Address */
    0xFE,
    /* Protocol Identifier */
    0x01,
    /* Instruction */
    0x4C,
    /* Key */
    0x00,
    /* Initiator Logical Address */
    0x67,
    /* Transaction Identifier MS */
    0x00,
    /* Transaction Identifier LS */
    0x01,
    /* Extended Address */
    0x00,
    /* Address MS */
    0xA0,
    /* Address */
    0x00,
    /* Address */
    0x00,
    /* Address LS */
    0x00,
    /* Data Length MS */
    0x00,
    /* Data Length */
    0x00,
    /* Data Length LS */
    0x10,
    /* Header CRC */
    0xC9};

static const uint8_t test_pattern1_expected_read_reply[] = {
    /* Initiator Logical Address */
    0x67,
    /* Protocol Identifier */
    0x01,
    /* Instruction */
    0x0C,
    /* Status */
    0x00,
    /* Target Logical Address */
    0xFE,
    /* Transaction Identifier MS */
    0x00,
    /* Transaction Identifier LS */
    0x01,
    /* Reserved */
    0x00,
    /* Data Length MS */
    0x00,
    /* Data Length */
    0x00,
    /* Data Length LS */
    0x10,
    /* Header CRC */
    0x6D,
    /* Data */
    0x01,
    0x23,
    0x45,
    0x67,
    0x89,
    0xAB,
    0xCD,
    0xEF,
    0x10,
    0x11,
    0x12,
    0x13,
    0x14,
    0x15,
    0x16,
    0x17,
    /* Data CRC */
    0x56};

static const size_t test_pattern2_target_address_length = 7;
static const size_t test_pattern2_reply_address_length_padded = 8;
static const uint8_t
    test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses
        [] = {
            /* Target SpaceWire Address */
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
            0x66,
            0x77,
            /* Target Logical Address */
            0xFE,
            /* Protocol Identifier */
            0x01,
            /* Instruction */
            0x6E,
            /* Key */
            0x00,
            /* Reply SpaceWire Address */
            0x00,
            0x99,
            0xAA,
            0xBB,
            0xCC,
            0xDD,
            0xEE,
            0x00,
            /* Initiator Logical Address */
            0x67,
            /* Transaction Identifier MS */
            0x00,
            /* Transaction Identifier LS */
            0x02,
            /* Extended Address */
            0x00,
            /* Address MS */
            0xA0,
            /* Address */
            0x00,
            /* Address */
            0x00,
            /* Address LS */
            0x10,
            /* Data Length MS */
            0x00,
            /* Data Length */
            0x00,
            /* Data Length LS */
            0x10,
            /* Header CRC */
            0x7F,
            /* Data */
            0xA0,
            0xA1,
            0xA2,
            0xA3,
            0xA4,
            0xA5,
            0xA6,
            0xA7,
            0xA8,
            0xA9,
            0xAA,
            0xAB,
            0xAC,
            0xAD,
            0xAE,
            0xAF,
            /* Data CRC */
            0xB4};

static const size_t test_pattern2_reply_address_length = 7;
static const uint8_t
    test_pattern2_expected_write_reply_with_spacewire_addresses[] = {
        /* Reply SpaceWire Address */
        0x99,
        0xAA,
        0xBB,
        0xCC,
        0xDD,
        0xEE,
        0x00,
        /* Initiator Logical Address */
        0x67,
        /* Protocol Identifier */
        0x01,
        /* Instruction */
        0x2E,
        /* Status */
        0x00,
        /* Target Logical Address */
        0xFE,
        /* Transaction Identifier MS */
        0x00,
        /* Transaction Identifier LS */
        0x02,
        /* Header CRC */
        0x1D};

static const size_t test_pattern3_target_address_length = 4;
static const uint8_t
    test_pattern3_incrementing_read_with_spacewire_addresses[] = {
        /* Target SpaceWire Address */
        0x11,
        0x22,
        0x33,
        0x44,
        /* Target Logical Address */
        0xFE,
        /* Protocol Identifier */
        0x01,
        /* Instruction */
        0x4D,
        /* Key */
        0x00,
        /* Reply SpaceWire Address */
        0x99,
        0xAA,
        0xBB,
        0xCC,
        /* Initiator Logical Address */
        0x67,
        /* Transaction Identifier MS */
        0x00,
        /* Transaction Identifier LS */
        0x03,
        /* Extended Address */
        0x00,
        /* Address MS */
        0xA0,
        /* Address */
        0x00,
        /* Address */
        0x00,
        /* Address LS */
        0x10,
        /* Data Length MS */
        0x00,
        /* Data Length */
        0x00,
        /* Data Length LS */
        0x10,
        /* Header CRC */
        0xF7};

static const size_t test_pattern3_reply_address_length = 4;
static const uint8_t
    test_pattern3_expected_read_reply_with_spacewire_addresses[] = {
        /* Reply SpaceWire Address */
        0x99,
        0xAA,
        0xBB,
        0xCC,
        /* Initiator Logical Address */
        0x67,
        /* Protocol Identifier */
        0x01,
        /* Instruction */
        0x0D,
        /* Status */
        0x00,
        /* Target Logical Address */
        0xFE,
        /* Transaction Identifier MS */
        0x00,
        /* Transaction Identifier LS */
        0x03,
        /* Reserved */
        0x00,
        /* Data Length MS */
        0x00,
        /* Data Length */
        0x00,
        /* Data Length LS */
        0x10,
        /* Header CRC */
        0x52,
        /* Data */
        0xA0,
        0xA1,
        0xA2,
        0xA3,
        0xA4,
        0xA5,
        0xA6,
        0xA7,
        0xA8,
        0xA9,
        0xAA,
        0xAB,
        0xAC,
        0xAD,
        0xAE,
        0xAF,
        /* Data CRC */
        0xB4};

/* Custom test patterns for read-modify-write. */

static const uint8_t test_pattern4_rmw[] = {
    /* Target Logical Address */
    0xFE,
    /* Protocol Identifier */
    0x01,
    /* Instruction */
    0x5C,
    /* Key */
    0x00,
    /* Initiator Logical Address */
    0x67,
    /* Transaction Identifier MS */
    0x00,
    /* Transaction Identifier LS */
    0x04,
    /* Extended Address */
    0x00,
    /* Address MS */
    0xA0,
    /* Address */
    0x00,
    /* Address */
    0x00,
    /* Address LS */
    0x10,
    /* Data Length MS */
    0x00,
    /* Data Length */
    0x00,
    /* Data Length LS */
    0x06,
    /* Header CRC */
    0x9D,
    /* Data */
    0xC0,
    0x18,
    0x02,
    /* Mask */
    0xF0,
    0x3C,
    0x03,
    /* Data CRC */
    0xE3};

static const uint8_t test_pattern4_expected_rmw_reply[] = {
    /* Initiator Logical Address */
    0x67,
    /* Protocol Identifier */
    0x01,
    /* Instruction */
    0x1C,
    /* Status */
    0x00,
    /* Target Logical Address */
    0xFE,
    /* Transaction Identifier MS */
    0x00,
    /* Transaction Identifier LS */
    0x04,
    /* Reserved */
    0x00,
    /* Data Length MS */
    0x00,
    /* Data Length */
    0x00,
    /* Data Length LS */
    0x03,
    /* Header CRC */
    0x4F,
    /* Data */
    0xA0,
    0xA1,
    0xA2,
    /* Data CRC */
    0xD7};

static const size_t test_pattern5_target_address_length = 1;
static const size_t test_pattern5_reply_address_length_padded = 4;
static const uint8_t test_pattern5_rmw_with_spacewire_addresses[] = {
    /* Target SpaceWire Address */
    0x11,
    /* Target Logical Address */
    0xFE,
    /* Protocol Identifier */
    0x01,
    /* Instruction */
    0x5D,
    /* Key */
    0x00,
    /* Reply SpaceWire Address */
    0x00,
    0x00,
    0x00,
    0x88,
    /* Initiator Logical Address */
    0x67,
    /* Transaction Identifier MS */
    0x00,
    /* Transaction Identifier LS */
    0x05,
    /* Extended Address */
    0x00,
    /* Address MS */
    0xA0,
    /* Address */
    0x00,
    /* Address */
    0x00,
    /* Address LS */
    0x10,
    /* Data Length MS */
    0x00,
    /* Data Length */
    0x00,
    /* Data Length LS */
    0x08,
    /* Header CRC */
    0xC6,
    /* Data */
    0x07,
    0x02,
    0xA0,
    0x00,
    /* Mask */
    0x0F,
    0x83,
    0xE0,
    0xFF,
    /* Data CRC */
    0x1D};

static const size_t test_pattern5_reply_address_length = 1;
static const uint8_t
    test_pattern5_expected_rmw_reply_with_spacewire_addresses[] = {
        /* Reply SpaceWire Address */
        0x88,
        /* Initiator Logical Address */
        0x67,
        /* Protocol Identifier */
        0x01,
        /* Instruction */
        0x1D,
        /* Status */
        0x00,
        /* Target Logical Address */
        0xFE,
        /* Transaction Identifier MS */
        0x00,
        /* Transaction Identifier LS */
        0x05,
        /* Reserved */
        0x00,
        /* Data Length MS */
        0x00,
        /* Data Length */
        0x00,
        /* Data Length LS */
        0x04,
        /* Header CRC */
        0xFF,
        /* Data */
        0xE0,
        0x99,
        0xA2,
        0xA3,
        /* Data CRC */
        0x7D};

class MockCallbacks
{
  public:
    MOCK_METHOD(
        void *,
        Allocate,
        (struct rmap_node_context * context, size_t size));
    MOCK_METHOD(
        void,
        SendReply,
        (struct rmap_node_context * context, void *packet, size_t size));
    MOCK_METHOD(
        enum rmap_status_field_code,
        WriteRequest,
        (struct rmap_node_context * context,
         const struct rmap_node_target_request *request,
         const void *data));
    MOCK_METHOD(
        enum rmap_status_field_code,
        ReadRequest,
        (struct rmap_node_context * context,
         void *data,
         size_t *data_size,
         const struct rmap_node_target_request *request));
    MOCK_METHOD(
        enum rmap_status_field_code,
        RmwRequest,
        (struct rmap_node_context * context,
         void *read_data,
         size_t *read_data_size,
         const struct rmap_node_target_request *request,
         const void *data));
    MOCK_METHOD(
        void,
        ReceivedWriteReply,
        (struct rmap_node_context * context,
         uint16_t transaction_identifier,
         enum rmap_status_field_code status));
    MOCK_METHOD(
        void,
        ReceivedReadReply,
        (struct rmap_node_context * context,
         uint16_t transaction_identifier,
         enum rmap_status_field_code status,
         const void *data,
         size_t data_length));
    MOCK_METHOD(
        void,
        ReceivedRmwReply,
        (struct rmap_node_context * context,
         uint16_t transaction_identifier,
         enum rmap_status_field_code status,
         const void *data,
         size_t data_length));
};

struct mocked_callbacks_custom_context {
    class MockCallbacks *mock_callbacks;
};

static void *allocate_mock_wrapper(
    struct rmap_node_context *const context,
    const size_t size)
{
    struct mocked_callbacks_custom_context *const custom_context =
        reinterpret_cast<struct mocked_callbacks_custom_context *>(
            context->custom_context);
    return custom_context->mock_callbacks->Allocate(context, size);
}

static void send_reply_mock_wrapper(
    struct rmap_node_context *const context,
    void *const packet,
    const size_t size)
{
    struct mocked_callbacks_custom_context *const custom_context =
        reinterpret_cast<struct mocked_callbacks_custom_context *>(
            context->custom_context);
    custom_context->mock_callbacks->SendReply(context, packet, size);
}

static enum rmap_status_field_code write_request_mock_wrapper(
    struct rmap_node_context *const context,
    const struct rmap_node_target_request *const request,
    const void *const data)
{
    struct mocked_callbacks_custom_context *const custom_context =
        reinterpret_cast<struct mocked_callbacks_custom_context *>(
            context->custom_context);
    return custom_context->mock_callbacks->WriteRequest(context, request, data);
}

static enum rmap_status_field_code read_request_mock_wrapper(
    struct rmap_node_context *const context,
    void *const data,
    size_t *const data_size,
    const struct rmap_node_target_request *const request)
{
    struct mocked_callbacks_custom_context *const custom_context =
        reinterpret_cast<struct mocked_callbacks_custom_context *>(
            context->custom_context);
    return custom_context->mock_callbacks
        ->ReadRequest(context, data, data_size, request);
}

static enum rmap_status_field_code rmw_request_mock_wrapper(
    struct rmap_node_context *const context,
    void *const read_data,
    size_t *const read_data_size,
    const struct rmap_node_target_request *const request,
    const void *const data)
{
    struct mocked_callbacks_custom_context *const custom_context =
        reinterpret_cast<struct mocked_callbacks_custom_context *>(
            context->custom_context);
    return custom_context->mock_callbacks
        ->RmwRequest(context, read_data, read_data_size, request, data);
}

static void received_write_reply_mock_wrapper(
    struct rmap_node_context *const context,
    const uint16_t transaction_identifier,
    const enum rmap_status_field_code status)
{
    struct mocked_callbacks_custom_context *const custom_context =
        reinterpret_cast<struct mocked_callbacks_custom_context *>(
            context->custom_context);
    return custom_context->mock_callbacks->ReceivedWriteReply(
        context,
        transaction_identifier,
        status);
}

static void received_read_reply_mock_wrapper(
    struct rmap_node_context *const context,
    const uint16_t transaction_identifier,
    const enum rmap_status_field_code status,
    const void *const data,
    const size_t data_length)
{
    struct mocked_callbacks_custom_context *const custom_context =
        reinterpret_cast<struct mocked_callbacks_custom_context *>(
            context->custom_context);
    return custom_context->mock_callbacks->ReceivedReadReply(
        context,
        transaction_identifier,
        status,
        data,
        data_length);
}

static void received_rmw_reply_mock_wrapper(
    struct rmap_node_context *const context,
    const uint16_t transaction_identifier,
    const enum rmap_status_field_code status,
    const void *const data,
    const size_t data_length)
{
    struct mocked_callbacks_custom_context *const custom_context =
        reinterpret_cast<struct mocked_callbacks_custom_context *>(
            context->custom_context);
    return custom_context->mock_callbacks->ReceivedRmwReply(
        context,
        transaction_identifier,
        status,
        data,
        data_length);
}

class MockedTargetNode : public testing::Test
{
  protected:
    MockedTargetNode()
        : callbacks(
              {.initiator =
                   {.received_write_reply = nullptr,
                    .received_read_reply = nullptr,
                    .received_rmw_reply = nullptr},
               .target = {
                   .allocate = allocate_mock_wrapper,
                   .send_reply = send_reply_mock_wrapper,
                   .write_request = write_request_mock_wrapper,
                   .read_request = read_request_mock_wrapper,
                   .rmw_request = rmw_request_mock_wrapper,
               }})
    {
        const struct mocked_callbacks_custom_context custom_context_init = {
            .mock_callbacks = &mock_callbacks,
        };
        custom_context = custom_context_init;
        const struct rmap_node_initialize_flags flags = {
            .is_target = 1,
            .is_initiator = 0,
            .is_reply_for_unused_packet_type_enabled = 1,
        };
        rmap_node_initialize(&node_context, &custom_context, &callbacks, flags);
    }

    MockCallbacks mock_callbacks;
    struct rmap_node_context node_context;

  private:
    struct mocked_callbacks_custom_context custom_context;
    const struct rmap_node_callbacks callbacks;
};

class MockedInitiatorNode : public testing::Test
{
  protected:
    MockedInitiatorNode()
        : callbacks(
              {.initiator =
                   {.received_write_reply = received_write_reply_mock_wrapper,
                    .received_read_reply = received_read_reply_mock_wrapper,
                    .received_rmw_reply = received_rmw_reply_mock_wrapper},
               .target = {
                   .allocate = nullptr,
                   .send_reply = nullptr,
                   .write_request = nullptr,
                   .read_request = nullptr,
                   .rmw_request = nullptr,
               }})
    {
        const struct mocked_callbacks_custom_context custom_context_init = {
            .mock_callbacks = &mock_callbacks,
        };
        custom_context = custom_context_init;
        const struct rmap_node_initialize_flags flags = {
            .is_target = 0,
            .is_initiator = 1,
            .is_reply_for_unused_packet_type_enabled = 0,
        };
        rmap_node_initialize(&node_context, &custom_context, &callbacks, flags);
    }

    MockCallbacks mock_callbacks;
    struct rmap_node_context node_context;

  private:
    struct mocked_callbacks_custom_context custom_context;
    const struct rmap_node_callbacks callbacks;
};

TEST_F(MockedTargetNode, TestPattern0IncomingCommand)
{
    std::vector<uint8_t> allocation;
    EXPECT_CALL(mock_callbacks, Allocate)
        .WillOnce([&allocation](
                      struct rmap_node_context *const node_context,
                      const size_t size) {
            (void)node_context;
            allocation.resize(size);
            return allocation.data();
        });

    const uint8_t *const incoming_header =
        test_pattern0_unverified_incrementing_write_with_reply;
    const uint8_t *const incoming_data =
        incoming_header + rmap_calculate_header_size(incoming_header);
    struct rmap_node_target_request request;
    EXPECT_CALL(
        mock_callbacks,
        WriteRequest(testing::_, testing::_, incoming_data))
        .WillOnce(testing::DoAll(
            testing::SaveArgPointee<1>(&request),
            testing::Return(RMAP_STATUS_FIELD_CODE_SUCCESS)));

    const std::vector<uint8_t> expected_reply(
        test_pattern0_expected_write_reply,
        test_pattern0_expected_write_reply +
            sizeof(test_pattern0_expected_write_reply));

    void *reply_allocation_ptr;
    EXPECT_CALL(
        mock_callbacks,
        SendReply(testing::_, testing::_, expected_reply.size()))
        .WillOnce(testing::SaveArg<1>(&reply_allocation_ptr));

    rmap_node_handle_incoming(
        &node_context,
        test_pattern0_unverified_incrementing_write_with_reply,
        sizeof(test_pattern0_unverified_incrementing_write_with_reply));

    EXPECT_EQ(request.target_logical_address, 0xFE);
    EXPECT_EQ(request.key, 0x00);
    EXPECT_EQ(request.initiator_logical_address, 0x67);
    EXPECT_EQ(request.transaction_identifier, 0x00);
    EXPECT_EQ(request.extended_address, 0x00);
    EXPECT_EQ(request.address, 0xA0000000);
    EXPECT_EQ(request.data_length, 0x10);
    EXPECT_EQ(reply_allocation_ptr, allocation.data());

    allocation.resize(expected_reply.size());
    EXPECT_EQ(allocation, expected_reply);

    EXPECT_EQ(node_context.error_information, RMAP_NODE_OK);
}

TEST_F(MockedTargetNode, TestPattern1IncomingCommand)
{
    std::vector<uint8_t> allocation;
    EXPECT_CALL(mock_callbacks, Allocate)
        .WillOnce([&allocation](
                      struct rmap_node_context *const node_context,
                      const size_t size) {
            (void)node_context;
            allocation.resize(size);
            return allocation.data();
        });

    struct rmap_node_target_request request;
    EXPECT_CALL(mock_callbacks, ReadRequest)
        .WillOnce(testing::DoAll(
            testing::SaveArgPointee<3>(&request),
            [](struct rmap_node_context *const node_context,
               void *const data,
               size_t *const data_size,
               const struct rmap_node_target_request *const request) {
                (void)node_context;
                const std::vector<uint8_t> source_data = {
                    0x01,
                    0x23,
                    0x45,
                    0x67,
                    0x89,
                    0xAB,
                    0xCD,
                    0xEF,
                    0x10,
                    0x11,
                    0x12,
                    0x13,
                    0x14,
                    0x15,
                    0x16,
                    0x17,
                };
                assert(request->data_length == source_data.size());
                memcpy(data, source_data.data(), request->data_length);
                *data_size = request->data_length;
                return RMAP_STATUS_FIELD_CODE_SUCCESS;
            }));

    const std::vector<uint8_t> expected_reply(
        test_pattern1_expected_read_reply,
        test_pattern1_expected_read_reply +
            sizeof(test_pattern1_expected_read_reply));

    void *reply_allocation_ptr;
    EXPECT_CALL(
        mock_callbacks,
        SendReply(testing::_, testing::_, expected_reply.size()))
        .WillOnce(testing::SaveArg<1>(&reply_allocation_ptr));

    rmap_node_handle_incoming(
        &node_context,
        test_pattern1_incrementing_read,
        sizeof(test_pattern1_incrementing_read));

    EXPECT_EQ(request.target_logical_address, 0xFE);
    EXPECT_EQ(request.key, 0x00);
    EXPECT_EQ(request.initiator_logical_address, 0x67);
    EXPECT_EQ(request.transaction_identifier, 0x01);
    EXPECT_EQ(request.extended_address, 0x00);
    EXPECT_EQ(request.address, 0xA0000000);
    EXPECT_EQ(request.data_length, 0x10);
    EXPECT_EQ(reply_allocation_ptr, allocation.data());

    allocation.resize(expected_reply.size());
    EXPECT_EQ(allocation, expected_reply);

    EXPECT_EQ(node_context.error_information, RMAP_NODE_OK);
}

TEST_F(MockedTargetNode, TestPattern2IncomingCommand)
{
    std::vector<uint8_t> allocation;
    EXPECT_CALL(mock_callbacks, Allocate)
        .WillOnce([&allocation](
                      struct rmap_node_context *const node_context,
                      const size_t size) {
            (void)node_context;
            allocation.resize(size);
            return allocation.data();
        });

    const uint8_t *const incoming_header =
        test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses +
        test_pattern2_target_address_length;
    const uint8_t *const incoming_data =
        incoming_header + rmap_calculate_header_size(incoming_header);
    struct rmap_node_target_request request;
    EXPECT_CALL(
        mock_callbacks,
        WriteRequest(testing::_, testing::_, incoming_data))
        .WillOnce(testing::DoAll(
            testing::SaveArgPointee<1>(&request),
            testing::Return(RMAP_STATUS_FIELD_CODE_SUCCESS)));

    const std::vector<uint8_t> expected_reply(
        test_pattern2_expected_write_reply_with_spacewire_addresses,
        test_pattern2_expected_write_reply_with_spacewire_addresses +
            sizeof(
                test_pattern2_expected_write_reply_with_spacewire_addresses));

    void *reply_allocation_ptr;
    EXPECT_CALL(
        mock_callbacks,
        SendReply(testing::_, testing::_, expected_reply.size()))
        .WillOnce(testing::SaveArg<1>(&reply_allocation_ptr));

    rmap_node_handle_incoming(
        &node_context,
        test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses +
            test_pattern2_target_address_length,
        sizeof(
            test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses) -
            test_pattern2_target_address_length);

    EXPECT_EQ(request.target_logical_address, 0xFE);
    EXPECT_EQ(request.key, 0x00);
    EXPECT_EQ(request.initiator_logical_address, 0x67);
    EXPECT_EQ(request.transaction_identifier, 0x02);
    EXPECT_EQ(request.extended_address, 0x00);
    EXPECT_EQ(request.address, 0xA0000010);
    EXPECT_EQ(request.data_length, 0x10);
    EXPECT_EQ(reply_allocation_ptr, allocation.data());

    allocation.resize(expected_reply.size());
    EXPECT_EQ(allocation, expected_reply);

    EXPECT_EQ(node_context.error_information, RMAP_NODE_OK);
}

TEST_F(MockedTargetNode, TestPattern3IncomingCommand)
{
    std::vector<uint8_t> allocation;
    EXPECT_CALL(mock_callbacks, Allocate)
        .WillOnce([&allocation](
                      struct rmap_node_context *const node_context,
                      const size_t size) {
            (void)node_context;
            allocation.resize(size);
            return allocation.data();
        });

    struct rmap_node_target_request request;
    EXPECT_CALL(mock_callbacks, ReadRequest)
        .WillOnce(testing::DoAll(
            testing::SaveArgPointee<3>(&request),
            [](struct rmap_node_context *const node_context,
               void *const data,
               size_t *const data_size,
               const struct rmap_node_target_request *const request) {
                (void)node_context;
                const std::vector<uint8_t> source_data = {
                    0xA0,
                    0xA1,
                    0xA2,
                    0xA3,
                    0xA4,
                    0xA5,
                    0xA6,
                    0xA7,
                    0xA8,
                    0xA9,
                    0xAA,
                    0xAB,
                    0xAC,
                    0xAD,
                    0xAE,
                    0xAF,
                };
                assert(request->data_length == source_data.size());
                memcpy(data, source_data.data(), request->data_length);
                *data_size = request->data_length;
                return RMAP_STATUS_FIELD_CODE_SUCCESS;
            }));

    const std::vector<uint8_t> expected_reply(
        test_pattern3_expected_read_reply_with_spacewire_addresses,
        test_pattern3_expected_read_reply_with_spacewire_addresses +
            sizeof(test_pattern3_expected_read_reply_with_spacewire_addresses));

    void *reply_allocation_ptr;
    EXPECT_CALL(
        mock_callbacks,
        SendReply(testing::_, testing::_, expected_reply.size()))
        .WillOnce(testing::SaveArg<1>(&reply_allocation_ptr));

    rmap_node_handle_incoming(
        &node_context,
        test_pattern3_incrementing_read_with_spacewire_addresses +
            test_pattern3_target_address_length,
        sizeof(test_pattern3_incrementing_read_with_spacewire_addresses) -
            test_pattern3_target_address_length);

    EXPECT_EQ(request.target_logical_address, 0xFE);
    EXPECT_EQ(request.key, 0x00);
    EXPECT_EQ(request.initiator_logical_address, 0x67);
    EXPECT_EQ(request.transaction_identifier, 0x03);
    EXPECT_EQ(request.extended_address, 0x00);
    EXPECT_EQ(request.address, 0xA0000010);
    EXPECT_EQ(request.data_length, 0x10);
    EXPECT_EQ(reply_allocation_ptr, allocation.data());

    allocation.resize(expected_reply.size());
    EXPECT_EQ(allocation, expected_reply);

    EXPECT_EQ(node_context.error_information, RMAP_NODE_OK);
}

TEST_F(MockedTargetNode, TestPattern4IncomingCommand)
{
    std::vector<uint8_t> allocation;
    EXPECT_CALL(mock_callbacks, Allocate)
        .WillOnce([&allocation](
                      struct rmap_node_context *const node_context,
                      const size_t size) {
            (void)node_context;
            allocation.resize(size);
            return allocation.data();
        });

    const uint8_t *const incoming_header = test_pattern4_rmw;
    const uint8_t *const incoming_data =
        incoming_header + rmap_calculate_header_size(incoming_header);
    struct rmap_node_target_request request;
    EXPECT_CALL(
        mock_callbacks,
        RmwRequest(
            testing::_,
            testing::_,
            testing::_,
            testing::_,
            incoming_data))
        .WillOnce(testing::DoAll(
            testing::SaveArgPointee<3>(&request),
            [](struct rmap_node_context *const node_context,
               void *const read_data,
               size_t *const read_data_size,
               const struct rmap_node_target_request *const request,
               const void *const data) {
                (void)node_context;
                (void)data;
                const std::vector<uint8_t> source_data = {0xA0, 0xA1, 0xA2};
                assert(request->data_length / 2 == source_data.size());
                memcpy(read_data, source_data.data(), request->data_length / 2);
                *read_data_size = request->data_length / 2;
                return RMAP_STATUS_FIELD_CODE_SUCCESS;
            }));

    const std::vector<uint8_t> expected_reply(
        test_pattern4_expected_rmw_reply,
        test_pattern4_expected_rmw_reply +
            sizeof(test_pattern4_expected_rmw_reply));

    void *reply_allocation_ptr;
    EXPECT_CALL(
        mock_callbacks,
        SendReply(testing::_, testing::_, expected_reply.size()))
        .WillOnce(testing::SaveArg<1>(&reply_allocation_ptr));

    rmap_node_handle_incoming(
        &node_context,
        test_pattern4_rmw,
        sizeof(test_pattern4_rmw));

    EXPECT_EQ(request.target_logical_address, 0xFE);
    EXPECT_EQ(request.key, 0x00);
    EXPECT_EQ(request.initiator_logical_address, 0x67);
    EXPECT_EQ(request.transaction_identifier, 0x04);
    EXPECT_EQ(request.extended_address, 0x00);
    EXPECT_EQ(request.address, 0xA0000010);
    EXPECT_EQ(request.data_length, 0x06);
    EXPECT_EQ(reply_allocation_ptr, allocation.data());

    allocation.resize(expected_reply.size());
    EXPECT_EQ(allocation, expected_reply);

    EXPECT_EQ(node_context.error_information, RMAP_NODE_OK);
}

TEST_F(MockedTargetNode, TestPattern5IncomingCommand)
{
    std::vector<uint8_t> allocation;
    EXPECT_CALL(mock_callbacks, Allocate)
        .WillOnce([&allocation](
                      struct rmap_node_context *const node_context,
                      const size_t size) {
            (void)node_context;
            allocation.resize(size);
            return allocation.data();
        });

    const uint8_t *const incoming_header =
        test_pattern5_rmw_with_spacewire_addresses +
        test_pattern5_target_address_length;
    const uint8_t *const incoming_data =
        incoming_header + rmap_calculate_header_size(incoming_header);
    struct rmap_node_target_request request;
    EXPECT_CALL(
        mock_callbacks,
        RmwRequest(
            testing::_,
            testing::_,
            testing::_,
            testing::_,
            incoming_data))
        .WillOnce(testing::DoAll(
            testing::SaveArgPointee<3>(&request),
            [](struct rmap_node_context *const node_context,
               void *const read_data,
               size_t *const read_data_size,
               const struct rmap_node_target_request *const request,
               const void *const data) {
                (void)node_context;
                (void)data;
                const std::vector<uint8_t> source_data = {
                    0xE0,
                    0x99,
                    0xA2,
                    0xA3,
                };
                assert(request->data_length / 2 == source_data.size());
                memcpy(read_data, source_data.data(), request->data_length / 2);
                *read_data_size = request->data_length / 2;
                return RMAP_STATUS_FIELD_CODE_SUCCESS;
            }));

    const std::vector<uint8_t> expected_reply(
        test_pattern5_expected_rmw_reply_with_spacewire_addresses,
        test_pattern5_expected_rmw_reply_with_spacewire_addresses +
            sizeof(test_pattern5_expected_rmw_reply_with_spacewire_addresses));

    void *reply_allocation_ptr;
    EXPECT_CALL(
        mock_callbacks,
        SendReply(testing::_, testing::_, expected_reply.size()))
        .WillOnce(testing::SaveArg<1>(&reply_allocation_ptr));

    rmap_node_handle_incoming(
        &node_context,
        test_pattern5_rmw_with_spacewire_addresses +
            test_pattern5_target_address_length,
        sizeof(test_pattern5_rmw_with_spacewire_addresses) -
            test_pattern5_target_address_length);

    EXPECT_EQ(request.target_logical_address, 0xFE);
    EXPECT_EQ(request.key, 0x00);
    EXPECT_EQ(request.initiator_logical_address, 0x67);
    EXPECT_EQ(request.transaction_identifier, 0x05);
    EXPECT_EQ(request.extended_address, 0x00);
    EXPECT_EQ(request.address, 0xA0000010);
    EXPECT_EQ(request.data_length, 0x08);
    EXPECT_EQ(reply_allocation_ptr, allocation.data());

    allocation.resize(expected_reply.size());
    EXPECT_EQ(allocation, expected_reply);

    EXPECT_EQ(node_context.error_information, RMAP_NODE_OK);
}

TEST_F(MockedTargetNode, ValidIncomingRead)
{
    std::vector<uint8_t> incoming_packet(RMAP_COMMAND_HEADER_STATIC_SIZE + 32);
    const std::vector<uint8_t> reply_address = {0x01, 0x02, 0x03};

    /* Incoming read command. */
    ASSERT_EQ(
        rmap_initialize_header(
            incoming_packet.data(),
            incoming_packet.size(),
            RMAP_PACKET_TYPE_COMMAND,
            RMAP_COMMAND_CODE_REPLY | RMAP_COMMAND_CODE_INCREMENT,
            reply_address.size()),
        RMAP_OK);
    rmap_set_target_logical_address(incoming_packet.data(), 0xFE);
    rmap_set_key(incoming_packet.data(), 0x7E);
    rmap_set_reply_address(
        incoming_packet.data(),
        reply_address.data(),
        reply_address.size());
    rmap_set_initiator_logical_address(incoming_packet.data(), 0x67);
    rmap_set_transaction_identifier(incoming_packet.data(), 123);
    rmap_set_extended_address(incoming_packet.data(), 0x12);
    rmap_set_address(incoming_packet.data(), 0x3456789A);
    rmap_set_data_length(incoming_packet.data(), 234);
    rmap_calculate_and_set_header_crc(incoming_packet.data());
    incoming_packet.resize(rmap_calculate_header_size(incoming_packet.data()));

    std::vector<uint8_t> allocation;
    EXPECT_CALL(mock_callbacks, Allocate)
        .WillOnce([&allocation](
                      struct rmap_node_context *const node_context,
                      const size_t size) {
            (void)node_context;
            allocation.resize(size);
            return allocation.data();
        });

    struct rmap_node_target_request read_request;
    EXPECT_CALL(mock_callbacks, ReadRequest)
        .WillOnce(testing::DoAll(
            testing::SaveArgPointee<3>(&read_request),
            [](struct rmap_node_context *const node_context,
               void *const data,
               size_t *const data_size,
               const struct rmap_node_target_request *const request) {
                (void)node_context;
                memset(data, 0xDA, request->data_length);
                *data_size = request->data_length;
                return RMAP_STATUS_FIELD_CODE_SUCCESS;
            }));

    void *reply_allocation_ptr;
    EXPECT_CALL(
        mock_callbacks,
        SendReply(
            testing::_,
            testing::_,
            reply_address.size() + RMAP_READ_REPLY_HEADER_STATIC_SIZE + 234 +
                1))
        .WillOnce(testing::SaveArg<1>(&reply_allocation_ptr));

    rmap_node_handle_incoming(
        &node_context,
        incoming_packet.data(),
        incoming_packet.size());

    EXPECT_EQ(read_request.target_logical_address, 0xFE);
    EXPECT_EQ(read_request.key, 0x7E);
    EXPECT_EQ(read_request.initiator_logical_address, 0x67);
    EXPECT_EQ(read_request.transaction_identifier, 123);
    EXPECT_EQ(read_request.extended_address, 0x12);
    EXPECT_EQ(read_request.address, 0x3456789A);
    EXPECT_EQ(read_request.data_length, 234);
    EXPECT_EQ(reply_allocation_ptr, allocation.data());

    std::vector<uint8_t> expected_reply(
        reply_address.size() + RMAP_READ_REPLY_HEADER_STATIC_SIZE + 234 + 1,
        0xDA);
    size_t reply_header_offset;
    ASSERT_EQ(
        rmap_create_success_reply_from_command(
            expected_reply.data(),
            &reply_header_offset,
            expected_reply.size(),
            incoming_packet.data()),
        RMAP_OK);
    ASSERT_EQ(reply_header_offset, reply_address.size());
    const size_t reply_header_size =
        rmap_calculate_header_size(expected_reply.data() + reply_header_offset);
    const size_t data_offset = reply_header_offset + reply_header_size;
    ASSERT_EQ(data_offset + 234 + 1, expected_reply.size());
    expected_reply.back() =
        rmap_crc_calculate(expected_reply.data() + data_offset, 234);
    allocation.resize(expected_reply.size());
    EXPECT_EQ(allocation, expected_reply);

    EXPECT_EQ(node_context.error_information, RMAP_NODE_OK);
}

class IncomingToTargetRejectParams :
    public MockedTargetNode,
    public testing::WithParamInterface<std::tuple<
        std::function<std::vector<uint8_t>()>,
        enum rmap_node_status>>
{
};

TEST_P(IncomingToTargetRejectParams, Check)
{
    const auto incoming_packet_generator_fn = std::get<0>(GetParam());
    const auto expected_error_information = std::get<1>(GetParam());

    const auto incoming_packet = incoming_packet_generator_fn();

    /* Fail test on any unexpected callback. */
    struct mocked_callbacks_custom_context *const custom_context =
        reinterpret_cast<struct mocked_callbacks_custom_context *>(
            node_context.custom_context);
    testing::StrictMock<MockCallbacks> strict_mock_callbacks;
    custom_context->mock_callbacks = &strict_mock_callbacks;

    rmap_node_handle_incoming(
        &node_context,
        incoming_packet.data(),
        incoming_packet.size());
    EXPECT_EQ(node_context.error_information, expected_error_information);
}

INSTANTIATE_TEST_CASE_P(
    ReplyReceivedByTarget,
    IncomingToTargetRejectParams,
    testing::Combine(
        testing::Values(
            [] {
                return std::vector<uint8_t>(
                    test_pattern0_expected_write_reply,
                    test_pattern0_expected_write_reply +
                        sizeof(test_pattern0_expected_write_reply));
            },
            [] {
                return std::vector<uint8_t>(
                    test_pattern1_expected_read_reply,
                    test_pattern1_expected_read_reply +
                        sizeof(test_pattern1_expected_read_reply));
            },
            [] {
                std::vector<uint8_t> incoming_packet(
                    test_pattern2_expected_write_reply_with_spacewire_addresses +
                        test_pattern2_reply_address_length,
                    test_pattern2_expected_write_reply_with_spacewire_addresses +
                        sizeof(
                            test_pattern2_expected_write_reply_with_spacewire_addresses));
                return incoming_packet;
            },
            [] {
                std::vector<uint8_t> incoming_packet(
                    test_pattern3_expected_read_reply_with_spacewire_addresses +
                        test_pattern3_reply_address_length,
                    test_pattern3_expected_read_reply_with_spacewire_addresses +
                        sizeof(
                            test_pattern3_expected_read_reply_with_spacewire_addresses));
                return incoming_packet;
            },
            [] {
                std::vector<uint8_t> incoming_packet(
                    test_pattern4_expected_rmw_reply,
                    test_pattern4_expected_rmw_reply +
                        sizeof(test_pattern4_expected_rmw_reply));
                return incoming_packet;
            },
            [] {
                std::vector<uint8_t> incoming_packet(
                    test_pattern5_expected_rmw_reply_with_spacewire_addresses +
                        test_pattern5_reply_address_length,
                    test_pattern5_expected_rmw_reply_with_spacewire_addresses +
                        sizeof(
                            test_pattern5_expected_rmw_reply_with_spacewire_addresses));
                return incoming_packet;
            }),
        testing::Values(RMAP_NODE_REPLY_RECEIVED_BY_TARGET)));

INSTANTIATE_TEST_CASE_P(
    IncompleteHeader,
    IncomingToTargetRejectParams,
    testing::Combine(
        testing::Values(
            [] {
                std::vector<uint8_t> incoming_packet(
                    test_pattern0_unverified_incrementing_write_with_reply,
                    test_pattern0_unverified_incrementing_write_with_reply +
                        sizeof(
                            test_pattern0_unverified_incrementing_write_with_reply));
                incoming_packet.resize(
                    rmap_calculate_header_size(incoming_packet.data()) - 1);
                return incoming_packet;
            },
            [] {
                std::vector<uint8_t> incoming_packet(
                    test_pattern0_unverified_incrementing_write_with_reply,
                    test_pattern0_unverified_incrementing_write_with_reply +
                        sizeof(
                            test_pattern0_unverified_incrementing_write_with_reply));
                /* Only target logical address and protocol. */
                incoming_packet.resize(2);
                return incoming_packet;
            },
            [] {
                std::vector<uint8_t> incoming_packet(
                    test_pattern0_unverified_incrementing_write_with_reply,
                    test_pattern0_unverified_incrementing_write_with_reply +
                        sizeof(
                            test_pattern0_unverified_incrementing_write_with_reply));
                /* Only target logical address. */
                incoming_packet.resize(1);
                return incoming_packet;
            }),
        testing::Values(RMAP_NODE_EARLY_EOP)));

INSTANTIATE_TEST_CASE_P(
    HeaderCrcError,
    IncomingToTargetRejectParams,
    testing::Combine(
        testing::Values(
            [] {
                std::vector<uint8_t> incoming_packet(
                    test_pattern0_unverified_incrementing_write_with_reply,
                    test_pattern0_unverified_incrementing_write_with_reply +
                        sizeof(
                            test_pattern0_unverified_incrementing_write_with_reply));
                /* Flip a bit in the key field. */
                incoming_packet.at(3) ^= 1;
                return incoming_packet;
            },
            [] {
                std::vector<uint8_t> incoming_packet(
                    test_pattern0_unverified_incrementing_write_with_reply,
                    test_pattern0_unverified_incrementing_write_with_reply +
                        sizeof(
                            test_pattern0_unverified_incrementing_write_with_reply));
                const size_t header_size =
                    rmap_calculate_header_size(incoming_packet.data());
                /* Flip a bit in the CRC field. */
                incoming_packet.at(header_size - 1) ^= 1;
                return incoming_packet;
            }),
        testing::Values(RMAP_NODE_HEADER_CRC_ERROR)));

/* Packet with non-RMAP protocol should be silently discarded. */
INSTANTIATE_TEST_CASE_P(
    InvalidProtocol,
    IncomingToTargetRejectParams,
    testing::Combine(
        testing::Values(
            [] {
                std::vector<uint8_t> incoming_packet(
                    test_pattern0_unverified_incrementing_write_with_reply,
                    test_pattern0_unverified_incrementing_write_with_reply +
                        sizeof(
                            test_pattern0_unverified_incrementing_write_with_reply));
                /* Set non-RMAP protocol. */
                incoming_packet.at(1) = 0x00;
                rmap_calculate_and_set_header_crc(incoming_packet.data());
                return incoming_packet;
            },
            [] {
                std::vector<uint8_t> incoming_packet(
                    test_pattern0_unverified_incrementing_write_with_reply,
                    test_pattern0_unverified_incrementing_write_with_reply +
                        sizeof(
                            test_pattern0_unverified_incrementing_write_with_reply));
                /* Set non-RMAP protocol. */
                incoming_packet.at(1) = 0x02;
                rmap_calculate_and_set_header_crc(incoming_packet.data());
                return incoming_packet;
            }),
        testing::Values(RMAP_NODE_OK)));

TEST_F(MockedInitiatorNode, TestPattern0IncomingReply)
{
    const uint16_t expected_transaction_id = 0x00;
    EXPECT_CALL(
        mock_callbacks,
        ReceivedWriteReply(
            testing::_,
            expected_transaction_id,
            RMAP_STATUS_FIELD_CODE_SUCCESS));

    rmap_node_handle_incoming(
        &node_context,
        test_pattern0_expected_write_reply,
        sizeof(test_pattern0_expected_write_reply));

    EXPECT_EQ(node_context.error_information, RMAP_NODE_OK);
}

TEST_F(MockedInitiatorNode, TestPattern1IncomingReply)
{
    const uint8_t *const incoming_header = test_pattern1_expected_read_reply;
    const uint8_t *const incoming_data =
        incoming_header + rmap_calculate_header_size(incoming_header);

    const uint16_t expected_transaction_id = 0x01;
    EXPECT_CALL(
        mock_callbacks,
        ReceivedReadReply(
            testing::_,
            expected_transaction_id,
            RMAP_STATUS_FIELD_CODE_SUCCESS,
            incoming_data,
            rmap_get_data_length(incoming_header)));

    rmap_node_handle_incoming(
        &node_context,
        test_pattern1_expected_read_reply,
        sizeof(test_pattern1_expected_read_reply));

    EXPECT_EQ(node_context.error_information, RMAP_NODE_OK);
}

TEST_F(MockedInitiatorNode, TestPattern2IncomingReply)
{
    const uint16_t expected_transaction_id = 0x02;
    EXPECT_CALL(
        mock_callbacks,
        ReceivedWriteReply(
            testing::_,
            expected_transaction_id,
            RMAP_STATUS_FIELD_CODE_SUCCESS));

    rmap_node_handle_incoming(
        &node_context,
        test_pattern2_expected_write_reply_with_spacewire_addresses +
            test_pattern2_reply_address_length,
        sizeof(test_pattern2_expected_write_reply_with_spacewire_addresses) -
            test_pattern2_reply_address_length);

    EXPECT_EQ(node_context.error_information, RMAP_NODE_OK);
}

TEST_F(MockedInitiatorNode, TestPattern3IncomingReply)
{
    const uint8_t *const incoming_header =
        test_pattern3_expected_read_reply_with_spacewire_addresses +
        test_pattern3_reply_address_length;
    const uint8_t *const incoming_data =
        incoming_header + rmap_calculate_header_size(incoming_header);

    const uint16_t expected_transaction_id = 0x03;
    EXPECT_CALL(
        mock_callbacks,
        ReceivedReadReply(
            testing::_,
            expected_transaction_id,
            RMAP_STATUS_FIELD_CODE_SUCCESS,
            incoming_data,
            rmap_get_data_length(incoming_header)));

    rmap_node_handle_incoming(
        &node_context,
        test_pattern3_expected_read_reply_with_spacewire_addresses +
            test_pattern3_reply_address_length,
        sizeof(test_pattern3_expected_read_reply_with_spacewire_addresses) -
            test_pattern3_reply_address_length);

    EXPECT_EQ(node_context.error_information, RMAP_NODE_OK);
}

TEST_F(MockedInitiatorNode, TestPattern4IncomingReply)
{
    const uint8_t *const incoming_header = test_pattern4_expected_rmw_reply;
    const uint8_t *const incoming_data =
        incoming_header + rmap_calculate_header_size(incoming_header);

    const uint16_t expected_transaction_id = 0x04;
    EXPECT_CALL(
        mock_callbacks,
        ReceivedRmwReply(
            testing::_,
            expected_transaction_id,
            RMAP_STATUS_FIELD_CODE_SUCCESS,
            incoming_data,
            rmap_get_data_length(incoming_header)));

    rmap_node_handle_incoming(
        &node_context,
        test_pattern4_expected_rmw_reply,
        sizeof(test_pattern4_expected_rmw_reply));

    EXPECT_EQ(node_context.error_information, RMAP_NODE_OK);
}

TEST_F(MockedInitiatorNode, TestPattern5IncomingReply)
{
    const uint8_t *const incoming_header =
        test_pattern5_expected_rmw_reply_with_spacewire_addresses +
        test_pattern5_reply_address_length;
    const uint8_t *const incoming_data =
        incoming_header + rmap_calculate_header_size(incoming_header);

    const uint16_t expected_transaction_id = 0x05;
    EXPECT_CALL(
        mock_callbacks,
        ReceivedRmwReply(
            testing::_,
            expected_transaction_id,
            RMAP_STATUS_FIELD_CODE_SUCCESS,
            incoming_data,
            rmap_get_data_length(incoming_header)));

    rmap_node_handle_incoming(
        &node_context,
        test_pattern5_expected_rmw_reply_with_spacewire_addresses +
            test_pattern5_reply_address_length,
        sizeof(test_pattern5_expected_rmw_reply_with_spacewire_addresses) -
            test_pattern5_reply_address_length);

    EXPECT_EQ(node_context.error_information, RMAP_NODE_OK);
}

class IncomingToInitiatorRejectParams :
    public MockedInitiatorNode,
    public testing::WithParamInterface<std::tuple<
        std::function<std::vector<uint8_t>()>,
        enum rmap_node_status>>
{
};

TEST_P(IncomingToInitiatorRejectParams, Check)
{
    const auto incoming_packet_generator_fn = std::get<0>(GetParam());
    const auto expected_error_information = std::get<1>(GetParam());

    const auto incoming_packet = incoming_packet_generator_fn();

    /* Fail test on any unexpected callback. */
    struct mocked_callbacks_custom_context *const custom_context =
        reinterpret_cast<struct mocked_callbacks_custom_context *>(
            node_context.custom_context);
    testing::StrictMock<MockCallbacks> strict_mock_callbacks;
    custom_context->mock_callbacks = &strict_mock_callbacks;

    rmap_node_handle_incoming(
        &node_context,
        incoming_packet.data(),
        incoming_packet.size());
    EXPECT_EQ(node_context.error_information, expected_error_information);
}

INSTANTIATE_TEST_CASE_P(
    CommandReceivedByInitiator,
    IncomingToInitiatorRejectParams,
    testing::Combine(
        testing::Values(
            [] {
                return std::vector<uint8_t>(
                    test_pattern0_unverified_incrementing_write_with_reply,
                    test_pattern0_unverified_incrementing_write_with_reply +
                        sizeof(
                            test_pattern0_unverified_incrementing_write_with_reply));
            },
            [] {
                return std::vector<uint8_t>(
                    test_pattern1_incrementing_read,
                    test_pattern1_incrementing_read +
                        sizeof(test_pattern1_incrementing_read));
            },
            [] {
                std::vector<uint8_t> incoming_packet(
                    test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses +
                        test_pattern2_target_address_length,
                    test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses +
                        sizeof(
                            test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses));
                return incoming_packet;
            },
            [] {
                std::vector<uint8_t> incoming_packet(
                    test_pattern3_incrementing_read_with_spacewire_addresses +
                        test_pattern3_target_address_length,
                    test_pattern3_incrementing_read_with_spacewire_addresses +
                        sizeof(
                            test_pattern3_incrementing_read_with_spacewire_addresses));
                return incoming_packet;
            },
            [] {
                std::vector<uint8_t> incoming_packet(
                    test_pattern4_rmw,
                    test_pattern4_rmw + sizeof(test_pattern4_rmw));
                return incoming_packet;
            },
            [] {
                std::vector<uint8_t> incoming_packet(
                    test_pattern5_rmw_with_spacewire_addresses +
                        test_pattern5_target_address_length,
                    test_pattern5_rmw_with_spacewire_addresses +
                        sizeof(test_pattern5_rmw_with_spacewire_addresses));
                return incoming_packet;
            }),
        testing::Values(RMAP_NODE_COMMAND_RECEIVED_BY_INITIATOR)));

INSTANTIATE_TEST_CASE_P(
    IncompleteHeader,
    IncomingToInitiatorRejectParams,
    testing::Combine(
        testing::Values(
            [] {
                std::vector<uint8_t> incoming_packet(
                    test_pattern0_expected_write_reply,
                    test_pattern0_expected_write_reply +
                        sizeof(test_pattern0_expected_write_reply));
                incoming_packet.resize(
                    rmap_calculate_header_size(incoming_packet.data()) - 1);
                return incoming_packet;
            },
            [] {
                std::vector<uint8_t> incoming_packet(
                    test_pattern0_expected_write_reply,
                    test_pattern0_expected_write_reply +
                        sizeof(test_pattern0_expected_write_reply));
                /* Only target logical address and protocol. */
                incoming_packet.resize(2);
                return incoming_packet;
            },
            [] {
                std::vector<uint8_t> incoming_packet(
                    test_pattern0_expected_write_reply,
                    test_pattern0_expected_write_reply +
                        sizeof(test_pattern0_expected_write_reply));
                /* Only target logical address. */
                incoming_packet.resize(1);
                return incoming_packet;
            }),
        testing::Values(RMAP_NODE_EARLY_EOP)));

INSTANTIATE_TEST_CASE_P(
    HeaderCrcError,
    IncomingToInitiatorRejectParams,
    testing::Combine(
        testing::Values(
            [] {
                std::vector<uint8_t> incoming_packet(
                    test_pattern0_expected_write_reply,
                    test_pattern0_expected_write_reply +
                        sizeof(test_pattern0_expected_write_reply));
                /* Flip a bit in the status field. */
                incoming_packet.at(3) ^= 1;
                return incoming_packet;
            },
            [] {
                std::vector<uint8_t> incoming_packet(
                    test_pattern0_expected_write_reply,
                    test_pattern0_expected_write_reply +
                        sizeof(test_pattern0_expected_write_reply));
                const size_t header_size =
                    rmap_calculate_header_size(incoming_packet.data());
                /* Flip a bit in the CRC field. */
                incoming_packet.at(header_size - 1) ^= 1;
                return incoming_packet;
            }),
        testing::Values(RMAP_NODE_HEADER_CRC_ERROR)));

/* Packet with non-RMAP protocol should be silently discarded. */
INSTANTIATE_TEST_CASE_P(
    InvalidProtocol,
    IncomingToInitiatorRejectParams,
    testing::Combine(
        testing::Values(
            [] {
                std::vector<uint8_t> incoming_packet(
                    test_pattern0_expected_write_reply,
                    test_pattern0_expected_write_reply +
                        sizeof(test_pattern0_expected_write_reply));
                /* Set non-RMAP protocol. */
                incoming_packet.at(1) = 0x00;
                rmap_calculate_and_set_header_crc(incoming_packet.data());
                return incoming_packet;
            },
            [] {
                std::vector<uint8_t> incoming_packet(
                    test_pattern0_expected_write_reply,
                    test_pattern0_expected_write_reply +
                        sizeof(test_pattern0_expected_write_reply));
                /* Set non-RMAP protocol. */
                incoming_packet.at(1) = 0x02;
                rmap_calculate_and_set_header_crc(incoming_packet.data());
                return incoming_packet;
            }),
        testing::Values(RMAP_NODE_OK)));
