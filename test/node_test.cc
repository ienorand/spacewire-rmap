#include <gmock/gmock.h>
#include <gtest/gtest.h>

extern "C" {
#include "node.h"
}

#include "test_patterns.h"

TEST(NodeInitialize, NoTargetOrInitiator)
{
    struct rmap_node_context node_context;
    void *const custom_context = NULL;
    const struct rmap_node_callbacks callbacks = {};
    const struct rmap_node_initialize_flags flags = {
        .is_target = 0,
        .is_initiator = 0,
        .is_reply_for_unused_packet_type_enabled = 1,
    };
    EXPECT_EQ(
        rmap_node_initialize(&node_context, custom_context, &callbacks, flags),
        RMAP_NODE_NO_TARGET_OR_INITIATOR);
}

class MockCallbacks
{
  public:
    MOCK_METHOD(
        void *,
        Allocate,
        (struct rmap_node_context * context, size_t size));
    MOCK_METHOD(
        enum rmap_status,
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

static enum rmap_status send_reply_mock_wrapper(
    struct rmap_node_context *const context,
    void *const packet,
    const size_t size)
{
    struct mocked_callbacks_custom_context *const custom_context =
        reinterpret_cast<struct mocked_callbacks_custom_context *>(
            context->custom_context);
    return custom_context->mock_callbacks->SendReply(context, packet, size);
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
        : callbacks({
              .target =
                  {
                      .allocate = allocate_mock_wrapper,
                      .send_reply = send_reply_mock_wrapper,
                      .write_request = write_request_mock_wrapper,
                      .read_request = read_request_mock_wrapper,
                      .rmw_request = rmw_request_mock_wrapper,
                  },
              .initiator =
                  {
                      .received_write_reply = nullptr,
                      .received_read_reply = nullptr,
                      .received_rmw_reply = nullptr,
                  },
          })
    {
        const struct mocked_callbacks_custom_context custom_context_init = {
            .mock_callbacks = &mock_callbacks,
        };
        custom_context = custom_context_init;
    }

    void SetUp() override
    {
        const struct rmap_node_initialize_flags flags = {
            .is_target = 1,
            .is_initiator = 0,
            .is_reply_for_unused_packet_type_enabled = 1,
        };
        ASSERT_EQ(
            rmap_node_initialize(
                &node_context,
                &custom_context,
                &callbacks,
                flags),
            RMAP_OK);
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
        : callbacks({
              .target =
                  {
                      .allocate = nullptr,
                      .send_reply = nullptr,
                      .write_request = nullptr,
                      .read_request = nullptr,
                      .rmw_request = nullptr,
                  },
              .initiator =
                  {
                      .received_write_reply = received_write_reply_mock_wrapper,
                      .received_read_reply = received_read_reply_mock_wrapper,
                      .received_rmw_reply = received_rmw_reply_mock_wrapper,
                  },
          })
    {
        const struct mocked_callbacks_custom_context custom_context_init = {
            .mock_callbacks = &mock_callbacks,
        };
        custom_context = custom_context_init;
    }

    void SetUp() override
    {
        const struct rmap_node_initialize_flags flags = {
            .is_target = 0,
            .is_initiator = 1,
            .is_reply_for_unused_packet_type_enabled = 0,
        };
        ASSERT_EQ(
            rmap_node_initialize(
                &node_context,
                &custom_context,
                &callbacks,
                flags),
            RMAP_OK);
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

    auto command_pattern =
        test_pattern0_unverified_incrementing_write_with_reply;
    const std::vector<uint8_t> command_packet(
        command_pattern.data.begin() + command_pattern.header_offset,
        command_pattern.data.end());
    const uint8_t *const incoming_data = command_packet.data() +
        rmap_calculate_header_size(command_packet.data());
    struct rmap_node_target_request request;
    EXPECT_CALL(
        mock_callbacks,
        WriteRequest(testing::_, testing::_, incoming_data))
        .WillOnce(testing::DoAll(
            testing::SaveArgPointee<1>(&request),
            testing::Return(RMAP_STATUS_FIELD_CODE_SUCCESS)));

    const std::vector<uint8_t> expected_reply =
        test_pattern0_expected_write_reply.data;

    void *reply_allocation_ptr;
    EXPECT_CALL(
        mock_callbacks,
        SendReply(testing::_, testing::_, expected_reply.size()))
        .WillOnce(testing::DoAll(
            testing::SaveArg<1>(&reply_allocation_ptr),
            testing::Return(RMAP_OK)));

    EXPECT_EQ(
        rmap_node_handle_incoming(
            &node_context,
            command_packet.data(),
            command_packet.size()),
        RMAP_OK);

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

    auto command_pattern = test_pattern1_incrementing_read;
    const std::vector<uint8_t> command_packet(
        command_pattern.data.begin() + command_pattern.header_offset,
        command_pattern.data.end());
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

    const std::vector<uint8_t> expected_reply =
        test_pattern1_expected_read_reply.data;

    void *reply_allocation_ptr;
    EXPECT_CALL(
        mock_callbacks,
        SendReply(testing::_, testing::_, expected_reply.size()))
        .WillOnce(testing::DoAll(
            testing::SaveArg<1>(&reply_allocation_ptr),
            testing::Return(RMAP_OK)));

    EXPECT_EQ(
        rmap_node_handle_incoming(
            &node_context,
            command_packet.data(),
            command_packet.size()),
        RMAP_OK);

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

    auto command_pattern =
        test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses;
    const std::vector<uint8_t> command_packet(
        command_pattern.data.begin() + command_pattern.header_offset,
        command_pattern.data.end());
    const uint8_t *const incoming_data = command_packet.data() +
        rmap_calculate_header_size(command_packet.data());
    struct rmap_node_target_request request;
    EXPECT_CALL(
        mock_callbacks,
        WriteRequest(testing::_, testing::_, incoming_data))
        .WillOnce(testing::DoAll(
            testing::SaveArgPointee<1>(&request),
            testing::Return(RMAP_STATUS_FIELD_CODE_SUCCESS)));

    const std::vector<uint8_t> expected_reply =
        test_pattern2_expected_write_reply_with_spacewire_addresses.data;

    void *reply_allocation_ptr;
    EXPECT_CALL(
        mock_callbacks,
        SendReply(testing::_, testing::_, expected_reply.size()))
        .WillOnce(testing::DoAll(
            testing::SaveArg<1>(&reply_allocation_ptr),
            testing::Return(RMAP_OK)));

    EXPECT_EQ(
        rmap_node_handle_incoming(
            &node_context,
            command_packet.data(),
            command_packet.size()),
        RMAP_OK);

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

    auto command_pattern =
        test_pattern3_incrementing_read_with_spacewire_addresses;
    const std::vector<uint8_t> command_packet(
        command_pattern.data.begin() + command_pattern.header_offset,
        command_pattern.data.end());
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

    const std::vector<uint8_t> expected_reply =
        test_pattern3_expected_read_reply_with_spacewire_addresses.data;

    void *reply_allocation_ptr;
    EXPECT_CALL(
        mock_callbacks,
        SendReply(testing::_, testing::_, expected_reply.size()))
        .WillOnce(testing::DoAll(
            testing::SaveArg<1>(&reply_allocation_ptr),
            testing::Return(RMAP_OK)));

    EXPECT_EQ(
        rmap_node_handle_incoming(
            &node_context,
            command_packet.data(),
            command_packet.size()),
        RMAP_OK);

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

    auto command_pattern = test_pattern4_rmw;
    const std::vector<uint8_t> command_packet(
        command_pattern.data.begin() + command_pattern.header_offset,
        command_pattern.data.end());
    const uint8_t *const incoming_data = command_packet.data() +
        rmap_calculate_header_size(command_packet.data());
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

    const std::vector<uint8_t> expected_reply =
        test_pattern4_expected_rmw_reply.data;

    void *reply_allocation_ptr;
    EXPECT_CALL(
        mock_callbacks,
        SendReply(testing::_, testing::_, expected_reply.size()))
        .WillOnce(testing::DoAll(
            testing::SaveArg<1>(&reply_allocation_ptr),
            testing::Return(RMAP_OK)));

    EXPECT_EQ(
        rmap_node_handle_incoming(
            &node_context,
            command_packet.data(),
            command_packet.size()),
        RMAP_OK);

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

    auto command_pattern = test_pattern5_rmw_with_spacewire_addresses;
    const std::vector<uint8_t> command_packet(
        command_pattern.data.begin() + command_pattern.header_offset,
        command_pattern.data.end());
    const uint8_t *const incoming_data = command_packet.data() +
        rmap_calculate_header_size(command_packet.data());
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

    const std::vector<uint8_t> expected_reply =
        test_pattern5_expected_rmw_reply_with_spacewire_addresses.data;

    void *reply_allocation_ptr;
    EXPECT_CALL(
        mock_callbacks,
        SendReply(testing::_, testing::_, expected_reply.size()))
        .WillOnce(testing::DoAll(
            testing::SaveArg<1>(&reply_allocation_ptr),
            testing::Return(RMAP_OK)));

    EXPECT_EQ(
        rmap_node_handle_incoming(
            &node_context,
            command_packet.data(),
            command_packet.size()),
        RMAP_OK);

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
        .WillOnce(testing::DoAll(
            testing::SaveArg<1>(&reply_allocation_ptr),
            testing::Return(RMAP_OK)));

    EXPECT_EQ(
        rmap_node_handle_incoming(
            &node_context,
            incoming_packet.data(),
            incoming_packet.size()),
        RMAP_OK);

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
}

class IncomingToTargetRejectParams :
    public MockedTargetNode,
    public testing::WithParamInterface<
        std::tuple<std::function<std::vector<uint8_t>()>, enum rmap_status>>
{
};

TEST_P(IncomingToTargetRejectParams, Check)
{
    const auto incoming_packet_generator_fn = std::get<0>(GetParam());
    const auto expected_status = std::get<1>(GetParam());

    const auto incoming_packet = incoming_packet_generator_fn();

    /* Fail test on any unexpected callback. */
    struct mocked_callbacks_custom_context *const custom_context =
        reinterpret_cast<struct mocked_callbacks_custom_context *>(
            node_context.custom_context);
    testing::StrictMock<MockCallbacks> strict_mock_callbacks;
    custom_context->mock_callbacks = &strict_mock_callbacks;

    EXPECT_EQ(
        rmap_node_handle_incoming(
            &node_context,
            incoming_packet.data(),
            incoming_packet.size()),
        expected_status);
}

INSTANTIATE_TEST_SUITE_P(
    ReplyReceivedByTarget,
    IncomingToTargetRejectParams,
    testing::Combine(
        testing::Values(
            [] {
                auto pattern = test_pattern0_expected_write_reply;
                return std::vector<uint8_t>(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
            },
            [] {
                auto pattern = test_pattern1_expected_read_reply;
                return std::vector<uint8_t>(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
            },
            [] {
                auto pattern =
                    test_pattern2_expected_write_reply_with_spacewire_addresses;
                return std::vector<uint8_t>(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
            },
            [] {
                auto pattern =
                    test_pattern3_expected_read_reply_with_spacewire_addresses;
                return std::vector<uint8_t>(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
            },
            [] {
                auto pattern = test_pattern4_expected_rmw_reply;
                return std::vector<uint8_t>(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
            },
            [] {
                auto pattern =
                    test_pattern5_expected_rmw_reply_with_spacewire_addresses;
                return std::vector<uint8_t>(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
            }),
        testing::Values(RMAP_NODE_REPLY_RECEIVED_BY_TARGET)));

INSTANTIATE_TEST_SUITE_P(
    IncompleteHeader,
    IncomingToTargetRejectParams,
    testing::Combine(
        testing::Values(
            [] {
                auto pattern =
                    test_pattern0_unverified_incrementing_write_with_reply;
                std::vector<uint8_t> incoming_packet(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
                incoming_packet.resize(
                    rmap_calculate_header_size(incoming_packet.data()) - 1);
                return incoming_packet;
            },
            [] {
                auto pattern =
                    test_pattern0_unverified_incrementing_write_with_reply;
                std::vector<uint8_t> incoming_packet(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
                /* Only target logical address and protocol. */
                incoming_packet.resize(2);
                return incoming_packet;
            },
            [] {
                auto pattern =
                    test_pattern0_unverified_incrementing_write_with_reply;
                std::vector<uint8_t> incoming_packet(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
                /* Only target logical address. */
                incoming_packet.resize(1);
                return incoming_packet;
            }),
        testing::Values(RMAP_INCOMPLETE_HEADER)));

INSTANTIATE_TEST_SUITE_P(
    HeaderCrcError,
    IncomingToTargetRejectParams,
    testing::Combine(
        testing::Values(
            [] {
                auto pattern =
                    test_pattern0_unverified_incrementing_write_with_reply;
                std::vector<uint8_t> incoming_packet(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
                /* Flip a bit in the key field. */
                incoming_packet.at(3) ^= 1;
                return incoming_packet;
            },
            [] {
                auto pattern =
                    test_pattern0_unverified_incrementing_write_with_reply;
                std::vector<uint8_t> incoming_packet(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
                const size_t header_size =
                    rmap_calculate_header_size(incoming_packet.data());
                /* Flip a bit in the CRC field. */
                incoming_packet.at(header_size - 1) ^= 1;
                return incoming_packet;
            }),
        testing::Values(RMAP_HEADER_CRC_ERROR)));

INSTANTIATE_TEST_SUITE_P(
    InvalidProtocol,
    IncomingToTargetRejectParams,
    testing::Combine(
        testing::Values(
            [] {
                auto pattern =
                    test_pattern0_unverified_incrementing_write_with_reply;
                std::vector<uint8_t> incoming_packet(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
                /* Set non-RMAP protocol. */
                incoming_packet.at(1) = 0x00;
                rmap_calculate_and_set_header_crc(incoming_packet.data());
                return incoming_packet;
            },
            [] {
                auto pattern =
                    test_pattern0_unverified_incrementing_write_with_reply;
                std::vector<uint8_t> incoming_packet(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
                /* Set non-RMAP protocol. */
                incoming_packet.at(1) = 0x02;
                rmap_calculate_and_set_header_crc(incoming_packet.data());
                return incoming_packet;
            }),
        testing::Values(RMAP_NO_RMAP_PROTOCOL)));

TEST(
    HandleIncoming,
    CommandWithUnusedPacketTypeWitReplyForUnusedPacketTypeDisabled)
{
    struct rmap_node_context node_context;
    MockCallbacks mock_callbacks;

    const struct rmap_node_callbacks callbacks = {
        .target =
            {
                .allocate = allocate_mock_wrapper,
                .send_reply = send_reply_mock_wrapper,
                .write_request = write_request_mock_wrapper,
                .read_request = read_request_mock_wrapper,
                .rmw_request = rmw_request_mock_wrapper,
            },
        .initiator =
            {
                .received_write_reply = NULL,
                .received_read_reply = NULL,
                .received_rmw_reply = NULL,
            },
    };
    struct mocked_callbacks_custom_context custom_context = {
        .mock_callbacks = &mock_callbacks,
    };
    const struct rmap_node_initialize_flags flags = {
        .is_target = 1,
        .is_initiator = 0,
        .is_reply_for_unused_packet_type_enabled = 0,
    };
    ASSERT_EQ(
        rmap_node_initialize(&node_context, &custom_context, &callbacks, flags),
        RMAP_OK);

    auto pattern = test_pattern0_unverified_incrementing_write_with_reply;
    const std::vector<uint8_t> original_packet(
        pattern.data.begin() + pattern.header_offset,
        pattern.data.end());
    std::vector<uint8_t> incoming_packet = original_packet;
    const uint8_t instruction = rmap_get_instruction(incoming_packet.data());
    /* Set reserved bit in packet type field. */
    rmap_set_instruction(incoming_packet.data(), instruction | 1 << 7);
    rmap_calculate_and_set_header_crc(incoming_packet.data());

    EXPECT_CALL(mock_callbacks, Allocate).Times(0);
    EXPECT_CALL(mock_callbacks, SendReply).Times(0);

    EXPECT_EQ(
        rmap_node_handle_incoming(
            &node_context,
            incoming_packet.data(),
            incoming_packet.size()),
        RMAP_UNUSED_PACKET_TYPE);
}

TEST(
    HandleIncoming,
    CommandWithUnusedPacketTypeWithReplyForUnusedPacketTypeTargetEnabled)
{
    struct rmap_node_context node_context;
    MockCallbacks mock_callbacks;

    const struct rmap_node_callbacks callbacks = {
        .target =
            {
                .allocate = allocate_mock_wrapper,
                .send_reply = send_reply_mock_wrapper,
                .write_request = write_request_mock_wrapper,
                .read_request = read_request_mock_wrapper,
                .rmw_request = rmw_request_mock_wrapper,
            },
        .initiator =
            {
                .received_write_reply = NULL,
                .received_read_reply = NULL,
                .received_rmw_reply = NULL,
            },
    };
    struct mocked_callbacks_custom_context custom_context = {
        .mock_callbacks = &mock_callbacks,
    };
    const struct rmap_node_initialize_flags flags = {
        .is_target = 1,
        .is_initiator = 0,
        .is_reply_for_unused_packet_type_enabled = 1,
    };
    ASSERT_EQ(
        rmap_node_initialize(&node_context, &custom_context, &callbacks, flags),
        RMAP_OK);

    auto pattern = test_pattern0_unverified_incrementing_write_with_reply;
    const std::vector<uint8_t> original_packet(
        pattern.data.begin() + pattern.header_offset,
        pattern.data.end());
    std::vector<uint8_t> incoming_packet = original_packet;
    const uint8_t instruction = rmap_get_instruction(incoming_packet.data());
    /* Set reserved bit in packet type field. */
    rmap_set_instruction(incoming_packet.data(), instruction | 1 << 7);
    rmap_calculate_and_set_header_crc(incoming_packet.data());

    std::vector<uint8_t> expected_reply(
        pattern.reply_address_length + RMAP_WRITE_REPLY_HEADER_STATIC_SIZE);
    size_t reply_header_offset;
    ASSERT_EQ(
        rmap_create_success_reply_from_command(
            expected_reply.data(),
            &reply_header_offset,
            expected_reply.size(),
            original_packet.data()),
        RMAP_OK);
    ASSERT_EQ(reply_header_offset, pattern.reply_address_length);
    rmap_set_status(
        expected_reply.data(),
        RMAP_STATUS_FIELD_CODE_UNUSED_PACKET_TYPE_OR_COMMAND_CODE);
    rmap_calculate_and_set_header_crc(expected_reply.data());

    std::vector<uint8_t> allocation;
    EXPECT_CALL(mock_callbacks, Allocate)
        .WillOnce([&allocation](
                      struct rmap_node_context *const node_context,
                      const size_t size) {
            (void)node_context;
            allocation.resize(size);
            return allocation.data();
        });

    void *reply_allocation_ptr;
    EXPECT_CALL(
        mock_callbacks,
        SendReply(testing::_, testing::_, expected_reply.size()))
        .WillOnce(testing::DoAll(
            testing::SaveArg<1>(&reply_allocation_ptr),
            testing::Return(RMAP_OK)));

    EXPECT_EQ(
        rmap_node_handle_incoming(
            &node_context,
            incoming_packet.data(),
            incoming_packet.size()),
        RMAP_UNUSED_PACKET_TYPE);
}

class IncomingToTargetRejectWithReplyParams :
    public MockedTargetNode,
    public testing::WithParamInterface<std::tuple<
        std::function<std::vector<uint8_t>()>,
        std::function<std::vector<uint8_t>()>,
        enum rmap_status>>
{
};

TEST_P(IncomingToTargetRejectWithReplyParams, Check)
{
    const auto incoming_packet_generator_fn = std::get<0>(GetParam());
    const auto expected_reply_generator_fn = std::get<1>(GetParam());
    const auto expected_status = std::get<2>(GetParam());

    const auto incoming_packet = incoming_packet_generator_fn();
    const auto expected_reply = expected_reply_generator_fn();

    std::vector<uint8_t> allocation;
    EXPECT_CALL(mock_callbacks, Allocate)
        .WillOnce([&allocation](
                      struct rmap_node_context *const node_context,
                      const size_t size) {
            (void)node_context;
            allocation.resize(size);
            return allocation.data();
        });

    void *reply_allocation_ptr;
    EXPECT_CALL(
        mock_callbacks,
        SendReply(testing::_, testing::_, expected_reply.size()))
        .WillOnce(testing::DoAll(
            testing::SaveArg<1>(&reply_allocation_ptr),
            testing::Return(RMAP_OK)));

    EXPECT_EQ(
        rmap_node_handle_incoming(
            &node_context,
            incoming_packet.data(),
            incoming_packet.size()),
        expected_status);

    allocation.resize(expected_reply.size());
    EXPECT_EQ(allocation, expected_reply);
}

INSTANTIATE_TEST_SUITE_P(
    UnusedCommandCode,
    IncomingToTargetRejectWithReplyParams,
    testing::Values(std::make_tuple(
        [] {
            auto pattern = test_pattern1_incrementing_read;
            std::vector<uint8_t> incoming_packet(
                pattern.data.begin() + pattern.header_offset,
                pattern.data.end());
            const uint8_t instruction =
                rmap_get_instruction(incoming_packet.data());
            /* Set verify bit and clear increment bit to create an invalid
             * command code (read, verified, non-incrementing, with reply).
             */
            rmap_set_instruction(
                incoming_packet.data(),
                (instruction | RMAP_COMMAND_CODE_VERIFY << 2) &
                    ~(RMAP_COMMAND_CODE_INCREMENT << 2));
            rmap_calculate_and_set_header_crc(incoming_packet.data());

            return incoming_packet;
        },
        [] {
            auto pattern = test_pattern1_expected_read_reply;
            std::vector<uint8_t> expected_reply = pattern.data;
            uint8_t *const header =
                expected_reply.data() + pattern.header_offset;
            rmap_set_status(
                header,
                RMAP_STATUS_FIELD_CODE_UNUSED_PACKET_TYPE_OR_COMMAND_CODE);
            rmap_set_instruction(
                header,
                RMAP_PACKET_TYPE_REPLY << 6 |
                    (RMAP_COMMAND_CODE_VERIFY | RMAP_COMMAND_CODE_REPLY) << 2);
            rmap_set_data_length(header, 0);
            rmap_calculate_and_set_header_crc(header);
            expected_reply.resize(rmap_calculate_header_size(header) + 1);
            expected_reply.back() =
                rmap_crc_calculate(&expected_reply.back(), 0);
            return expected_reply;
        },
        RMAP_UNUSED_COMMAND_CODE)));

INSTANTIATE_TEST_SUITE_P(
    InsufficientData,
    IncomingToTargetRejectWithReplyParams,
    testing::Values(std::make_tuple(
        [] {
            auto pattern =
                test_pattern0_unverified_incrementing_write_with_reply;
            std::vector<uint8_t> incoming_packet(
                pattern.data.begin() + pattern.header_offset,
                pattern.data.end());
            incoming_packet.pop_back();
            return incoming_packet;
        },
        [] {
            auto pattern = test_pattern0_expected_write_reply;
            std::vector<uint8_t> expected_reply = pattern.data;
            uint8_t *const header =
                expected_reply.data() + pattern.header_offset;
            rmap_set_status(header, RMAP_STATUS_FIELD_CODE_EARLY_EOP);
            rmap_calculate_and_set_header_crc(header);
            return expected_reply;
        },
        RMAP_INSUFFICIENT_DATA)));

INSTANTIATE_TEST_SUITE_P(
    TooMuchData,
    IncomingToTargetRejectWithReplyParams,
    testing::Values(std::make_tuple(
        [] {
            auto pattern =
                test_pattern0_unverified_incrementing_write_with_reply;
            std::vector<uint8_t> incoming_packet(
                pattern.data.begin() + pattern.header_offset,
                pattern.data.end());
            incoming_packet.push_back(0xDA);
            return incoming_packet;
        },
        [] {
            auto pattern = test_pattern0_expected_write_reply;
            std::vector<uint8_t> expected_reply = pattern.data;
            uint8_t *const header =
                expected_reply.data() + pattern.header_offset;
            rmap_set_status(header, RMAP_STATUS_FIELD_CODE_TOO_MUCH_DATA);
            rmap_calculate_and_set_header_crc(header);
            return expected_reply;
        },
        RMAP_TOO_MUCH_DATA)));

INSTANTIATE_TEST_SUITE_P(
    RmwDataLengthError,
    IncomingToTargetRejectWithReplyParams,
    testing::Values(std::make_tuple(
        [] {
            auto pattern = test_pattern4_rmw;
            std::vector<uint8_t> incoming_packet(
                pattern.data.begin() + pattern.header_offset,
                pattern.data.end());
            rmap_set_data_length(incoming_packet.data(), 3);
            rmap_calculate_and_set_header_crc(incoming_packet.data());
            const size_t data_offset =
                rmap_calculate_header_size(incoming_packet.data());
            incoming_packet.resize(data_offset + 3 + 1);
            incoming_packet.back() =
                rmap_crc_calculate(incoming_packet.data() + data_offset, 3);
            return incoming_packet;
        },
        [] {
            auto pattern = test_pattern4_expected_rmw_reply;
            std::vector<uint8_t> expected_reply = pattern.data;
            uint8_t *const header =
                expected_reply.data() + pattern.header_offset;
            rmap_set_status(
                header,
                RMAP_STATUS_FIELD_CODE_RMW_DATA_LENGTH_ERROR);
            rmap_set_data_length(header, 0);
            rmap_calculate_and_set_header_crc(header);
            expected_reply.resize(rmap_calculate_header_size(header) + 1);
            expected_reply.back() =
                rmap_crc_calculate(&expected_reply.back(), 0);
            return expected_reply;
        },
        RMAP_RMW_DATA_LENGTH_ERROR)));

INSTANTIATE_TEST_SUITE_P(
    InvalidDataCrc,
    IncomingToTargetRejectWithReplyParams,
    testing::Values(
        std::make_tuple(
            [] {
                auto pattern =
                    test_pattern0_unverified_incrementing_write_with_reply;
                std::vector<uint8_t> incoming_packet(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
                /* Flip a bit in data field. */
                incoming_packet.at(
                    rmap_calculate_header_size(incoming_packet.data())) ^= 1;
                return incoming_packet;
            },
            [] {
                auto pattern = test_pattern0_expected_write_reply;
                std::vector<uint8_t> expected_reply = pattern.data;
                uint8_t *const header =
                    expected_reply.data() + pattern.header_offset;
                rmap_set_status(
                    header,
                    RMAP_STATUS_FIELD_CODE_INVALID_DATA_CRC);
                rmap_calculate_and_set_header_crc(header);
                return expected_reply;
            },
            RMAP_INVALID_DATA_CRC),
        std::make_tuple(
            [] {
                auto pattern =
                    test_pattern0_unverified_incrementing_write_with_reply;
                std::vector<uint8_t> incoming_packet(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
                /* Flip a bit in data CRC field. */
                incoming_packet.back() ^= 1;
                return incoming_packet;
            },
            [] {
                auto pattern = test_pattern0_expected_write_reply;
                std::vector<uint8_t> expected_reply = pattern.data;
                uint8_t *const header =
                    expected_reply.data() + pattern.header_offset;
                rmap_set_status(
                    header,
                    RMAP_STATUS_FIELD_CODE_INVALID_DATA_CRC);
                rmap_calculate_and_set_header_crc(header);
                return expected_reply;
            },
            RMAP_INVALID_DATA_CRC)));

class IncomingToTargetAuthorizationRejectWithReplyParams :
    public MockedTargetNode,
    public testing::WithParamInterface<std::tuple<
        std::pair<struct test_pattern, struct test_pattern>,
        std::pair<enum rmap_status_field_code, enum rmap_status>>>
{
};

TEST_P(IncomingToTargetAuthorizationRejectWithReplyParams, Check)
{
    const auto command_reply_pair = std::get<0>(GetParam());
    const auto status_field_code = std::get<0>(std::get<1>(GetParam()));
    const auto expected_status = std::get<1>(std::get<1>(GetParam()));

    const auto incoming_pattern = std::get<0>(command_reply_pair);
    const std::vector<uint8_t> incoming_packet(
        incoming_pattern.data.begin() + incoming_pattern.header_offset,
        incoming_pattern.data.end());

    const auto expected_reply_pattern = std::get<1>(command_reply_pair);
    std::vector<uint8_t> expected_reply = expected_reply_pattern.data;
    uint8_t *const expected_reply_header =
        expected_reply.data() + expected_reply_pattern.header_offset;
    rmap_set_status(expected_reply_header, status_field_code);
    if (!rmap_is_write(expected_reply_header)) {
        /* RMW or read reply, contains data field, set data length to zero for
         * error reply.
         */
        rmap_set_data_length(expected_reply_header, 0);
        expected_reply.resize(
            expected_reply_pattern.header_offset +
            rmap_calculate_header_size(expected_reply_header) + 1);
        expected_reply.back() = rmap_crc_calculate(&expected_reply.back(), 0);
    }
    rmap_calculate_and_set_header_crc(expected_reply_header);

    ASSERT_NE(status_field_code, RMAP_STATUS_FIELD_CODE_SUCCESS);
    EXPECT_CALL(mock_callbacks, WriteRequest)
        .WillRepeatedly(testing::Return(status_field_code));
    EXPECT_CALL(mock_callbacks, ReadRequest)
        .WillRepeatedly(testing::Return(status_field_code));
    EXPECT_CALL(mock_callbacks, RmwRequest)
        .WillRepeatedly(testing::Return(status_field_code));

    std::vector<uint8_t> allocation;
    EXPECT_CALL(mock_callbacks, Allocate)
        .WillOnce([&allocation](
                      struct rmap_node_context *const node_context,
                      const size_t size) {
            (void)node_context;
            allocation.resize(size);
            return allocation.data();
        });

    void *reply_allocation_ptr;
    EXPECT_CALL(
        mock_callbacks,
        SendReply(testing::_, testing::_, expected_reply.size()))
        .WillOnce(testing::DoAll(
            testing::SaveArg<1>(&reply_allocation_ptr),
            testing::Return(RMAP_OK)));

    EXPECT_EQ(
        rmap_node_handle_incoming(
            &node_context,
            incoming_packet.data(),
            incoming_packet.size()),
        expected_status);

    allocation.resize(expected_reply.size());
    EXPECT_EQ(allocation, expected_reply);
}

INSTANTIATE_TEST_SUITE_P(
    CommonRejectsForAllCommands,
    IncomingToTargetAuthorizationRejectWithReplyParams,
    testing::Combine(
        testing::ValuesIn(test_patterns_command_reply_pairs),
        testing::Values(
            std::make_pair(
                RMAP_STATUS_FIELD_CODE_INVALID_KEY,
                RMAP_NODE_INVALID_KEY),
            std::make_pair(
                RMAP_STATUS_FIELD_CODE_INVALID_TARGET_LOGICAL_ADDRESS,
                RMAP_NODE_INVALID_TARGET_LOGICAL_ADDRESS),
            std::make_pair(
                RMAP_STATUS_FIELD_CODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED,
                RMAP_NODE_COMMAND_NOT_IMPLEMENTED_OR_NOT_AUTHORIZED))));

INSTANTIATE_TEST_SUITE_P(
    WriteError,
    IncomingToTargetAuthorizationRejectWithReplyParams,
    testing::Combine(
        testing::Values(
            std::make_pair(
                test_pattern0_unverified_incrementing_write_with_reply,
                test_pattern0_expected_write_reply),
            std::make_pair(
                test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses,
                test_pattern2_expected_write_reply_with_spacewire_addresses)),
        testing::Values(std::make_pair(
            RMAP_STATUS_FIELD_CODE_GENERAL_ERROR_CODE,
            RMAP_NODE_MEMORY_ACCESS_ERROR))));

class IncomingToTargetAuthorizationRejectWithReplyAndCallbackSetupParams :
    public MockedTargetNode,
    public testing::WithParamInterface<std::tuple<
        std::function<std::vector<uint8_t>()>,
        /* TODO: Remove (?). */
        enum rmap_status_field_code,
        std::function<void(MockCallbacks &, enum rmap_status_field_code)>,
        std::function<std::vector<uint8_t>(enum rmap_status_field_code)>,
        enum rmap_status>>
{
};

TEST_P(
    IncomingToTargetAuthorizationRejectWithReplyAndCallbackSetupParams,
    Check)
{
    const auto incoming_packet_generator_fn = std::get<0>(GetParam());
    const auto status_field_code = std::get<1>(GetParam());
    const auto callback_setup_fn = std::get<2>(GetParam());
    const auto expected_reply_generator_fn = std::get<3>(GetParam());
    const auto expected_status = std::get<4>(GetParam());

    const auto incoming_packet = incoming_packet_generator_fn();
    callback_setup_fn(mock_callbacks, status_field_code);
    const auto expected_reply = expected_reply_generator_fn(status_field_code);

    std::vector<uint8_t> allocation;
    EXPECT_CALL(mock_callbacks, Allocate)
        .WillOnce([&allocation](
                      struct rmap_node_context *const node_context,
                      const size_t size) {
            (void)node_context;
            allocation.resize(size);
            return allocation.data();
        });

    void *reply_allocation_ptr;
    EXPECT_CALL(
        mock_callbacks,
        SendReply(testing::_, testing::_, expected_reply.size()))
        .WillOnce(testing::DoAll(
            testing::SaveArg<1>(&reply_allocation_ptr),
            testing::Return(RMAP_OK)));

    EXPECT_EQ(
        rmap_node_handle_incoming(
            &node_context,
            incoming_packet.data(),
            incoming_packet.size()),
        expected_status);

    allocation.resize(expected_reply.size());
    EXPECT_EQ(allocation, expected_reply);
}

INSTANTIATE_TEST_SUITE_P(
    ReadError,
    IncomingToTargetAuthorizationRejectWithReplyAndCallbackSetupParams,
    testing::Values(std::make_tuple(
        [] {
            auto pattern = test_pattern1_incrementing_read;
            std::vector<uint8_t> incoming_packet(
                pattern.data.begin() + pattern.header_offset,
                pattern.data.end());
            return incoming_packet;
        },
        RMAP_STATUS_FIELD_CODE_GENERAL_ERROR_CODE,
        [](const MockCallbacks &mock_callbacks,
           const enum rmap_status_field_code status_field_code) {
            EXPECT_CALL(mock_callbacks, ReadRequest)
                .WillOnce(
                    [](struct rmap_node_context *const context,
                       void *const data,
                       size_t *const data_size,
                       const struct rmap_node_target_request *const request) {
                        (void)context;

                        std::vector<uint8_t> source_data = {
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
                        memcpy(
                            data,
                            source_data.data(),
                            source_data.size() - 1);
                        *data_size = source_data.size() - 1;
                        return RMAP_STATUS_FIELD_CODE_SUCCESS;
                    });
        },
        [](const enum rmap_status_field_code status_field_code) {
            auto pattern = test_pattern1_expected_read_reply;
            std::vector<uint8_t> expected_reply = pattern.data;
            uint8_t *const header =
                expected_reply.data() + pattern.header_offset;
            rmap_calculate_and_set_header_crc(header);
            assert(expected_reply.size() >= 1);
            expected_reply.resize(expected_reply.size() - 1);
            expected_reply.back() = rmap_crc_calculate(
                header + rmap_calculate_header_size(header),
                expected_reply.size() - pattern.header_offset -
                    rmap_calculate_header_size(header) - 1);
            return expected_reply;
        },
        RMAP_NODE_MEMORY_ACCESS_ERROR)));

/* TODO: Instantiate for RMW errors. */

TEST_F(MockedInitiatorNode, TestPattern0IncomingReply)
{
    const uint16_t expected_transaction_id = 0x00;
    EXPECT_CALL(
        mock_callbacks,
        ReceivedWriteReply(
            testing::_,
            expected_transaction_id,
            RMAP_STATUS_FIELD_CODE_SUCCESS));

    auto pattern = test_pattern0_expected_write_reply;
    const std::vector<uint8_t> incoming_packet(
        pattern.data.begin() + pattern.header_offset,
        pattern.data.end());
    EXPECT_EQ(
        rmap_node_handle_incoming(
            &node_context,
            incoming_packet.data(),
            incoming_packet.size()),
        RMAP_OK);
}

TEST_F(MockedInitiatorNode, TestPattern1IncomingReply)
{
    auto pattern = test_pattern1_expected_read_reply;
    const std::vector<uint8_t> incoming_packet(
        pattern.data.begin() + pattern.header_offset,
        pattern.data.end());
    const uint8_t *const incoming_data = incoming_packet.data() +
        rmap_calculate_header_size(incoming_packet.data());

    const uint16_t expected_transaction_id = 0x01;
    EXPECT_CALL(
        mock_callbacks,
        ReceivedReadReply(
            testing::_,
            expected_transaction_id,
            RMAP_STATUS_FIELD_CODE_SUCCESS,
            incoming_data,
            rmap_get_data_length(incoming_packet.data())));

    EXPECT_EQ(
        rmap_node_handle_incoming(
            &node_context,
            incoming_packet.data(),
            incoming_packet.size()),
        RMAP_OK);
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

    auto pattern = test_pattern2_expected_write_reply_with_spacewire_addresses;
    const std::vector<uint8_t> incoming_packet(
        pattern.data.begin() + pattern.header_offset,
        pattern.data.end());
    EXPECT_EQ(
        rmap_node_handle_incoming(
            &node_context,
            incoming_packet.data(),
            incoming_packet.size()),
        RMAP_OK);
}

TEST_F(MockedInitiatorNode, TestPattern3IncomingReply)
{
    auto pattern = test_pattern3_expected_read_reply_with_spacewire_addresses;
    const std::vector<uint8_t> incoming_packet(
        pattern.data.begin() + pattern.header_offset,
        pattern.data.end());
    const uint8_t *const incoming_data = incoming_packet.data() +
        rmap_calculate_header_size(incoming_packet.data());

    const uint16_t expected_transaction_id = 0x03;
    EXPECT_CALL(
        mock_callbacks,
        ReceivedReadReply(
            testing::_,
            expected_transaction_id,
            RMAP_STATUS_FIELD_CODE_SUCCESS,
            incoming_data,
            rmap_get_data_length(incoming_packet.data())));

    EXPECT_EQ(
        rmap_node_handle_incoming(
            &node_context,
            incoming_packet.data(),
            incoming_packet.size()),
        RMAP_OK);
}

TEST_F(MockedInitiatorNode, TestPattern4IncomingReply)
{
    auto pattern = test_pattern4_expected_rmw_reply;
    const std::vector<uint8_t> incoming_packet(
        pattern.data.begin() + pattern.header_offset,
        pattern.data.end());
    const uint8_t *const incoming_data = incoming_packet.data() +
        rmap_calculate_header_size(incoming_packet.data());

    const uint16_t expected_transaction_id = 0x04;
    EXPECT_CALL(
        mock_callbacks,
        ReceivedRmwReply(
            testing::_,
            expected_transaction_id,
            RMAP_STATUS_FIELD_CODE_SUCCESS,
            incoming_data,
            rmap_get_data_length(incoming_packet.data())));

    EXPECT_EQ(
        rmap_node_handle_incoming(
            &node_context,
            incoming_packet.data(),
            incoming_packet.size()),
        RMAP_OK);
}

TEST_F(MockedInitiatorNode, TestPattern5IncomingReply)
{
    auto pattern = test_pattern5_expected_rmw_reply_with_spacewire_addresses;
    const std::vector<uint8_t> incoming_packet(
        pattern.data.begin() + pattern.header_offset,
        pattern.data.end());
    const uint8_t *const incoming_data = incoming_packet.data() +
        rmap_calculate_header_size(incoming_packet.data());

    const uint16_t expected_transaction_id = 0x05;
    EXPECT_CALL(
        mock_callbacks,
        ReceivedRmwReply(
            testing::_,
            expected_transaction_id,
            RMAP_STATUS_FIELD_CODE_SUCCESS,
            incoming_data,
            rmap_get_data_length(incoming_packet.data())));

    EXPECT_EQ(
        rmap_node_handle_incoming(
            &node_context,
            incoming_packet.data(),
            incoming_packet.size()),
        RMAP_OK);
}

TEST_F(MockedTargetNode, IncomingCommandWithReplyAllocationFailure)
{
    EXPECT_CALL(mock_callbacks, WriteRequest)
        .WillOnce(testing::Return(RMAP_STATUS_FIELD_CODE_SUCCESS));
    EXPECT_CALL(mock_callbacks, Allocate).WillOnce(testing::Return(nullptr));
    EXPECT_CALL(mock_callbacks, SendReply).Times(0);

    auto command_pattern =
        test_pattern0_unverified_incrementing_write_with_reply;
    const std::vector<uint8_t> command_packet(
        command_pattern.data.begin() + command_pattern.header_offset,
        command_pattern.data.end());
    EXPECT_EQ(
        rmap_node_handle_incoming(
            &node_context,
            command_packet.data(),
            command_packet.size()),
        RMAP_NODE_ALLOCATION_FAILURE);
}

TEST_F(MockedTargetNode, IncomingCommandWithReplySendFailure)
{
    EXPECT_CALL(mock_callbacks, WriteRequest)
        .WillOnce(testing::Return(RMAP_STATUS_FIELD_CODE_SUCCESS));

    std::vector<uint8_t> allocation;
    EXPECT_CALL(mock_callbacks, Allocate)
        .WillOnce([&allocation](
                      struct rmap_node_context *const node_context,
                      const size_t size) {
            (void)node_context;
            allocation.resize(size);
            return allocation.data();
        });

    EXPECT_CALL(mock_callbacks, SendReply)
        .WillOnce(testing::Return(RMAP_NODE_SEND_REPLY_FAILURE));

    auto command_pattern =
        test_pattern0_unverified_incrementing_write_with_reply;
    const std::vector<uint8_t> command_packet(
        command_pattern.data.begin() + command_pattern.header_offset,
        command_pattern.data.end());
    EXPECT_EQ(
        rmap_node_handle_incoming(
            &node_context,
            command_packet.data(),
            command_packet.size()),
        RMAP_NODE_SEND_REPLY_FAILURE);
}

class IncomingToInitiatorRejectParams :
    public MockedInitiatorNode,
    public testing::WithParamInterface<
        std::tuple<std::function<std::vector<uint8_t>()>, enum rmap_status>>
{
};

TEST_P(IncomingToInitiatorRejectParams, Check)
{
    const auto incoming_packet_generator_fn = std::get<0>(GetParam());
    const auto expected_status = std::get<1>(GetParam());

    const auto incoming_packet = incoming_packet_generator_fn();

    /* Fail test on any unexpected callback. */
    struct mocked_callbacks_custom_context *const custom_context =
        reinterpret_cast<struct mocked_callbacks_custom_context *>(
            node_context.custom_context);
    testing::StrictMock<MockCallbacks> strict_mock_callbacks;
    custom_context->mock_callbacks = &strict_mock_callbacks;

    EXPECT_EQ(
        rmap_node_handle_incoming(
            &node_context,
            incoming_packet.data(),
            incoming_packet.size()),
        expected_status);
}

INSTANTIATE_TEST_SUITE_P(
    CommandReceivedByInitiator,
    IncomingToInitiatorRejectParams,
    testing::Combine(
        testing::Values(
            [] {
                auto pattern =
                    test_pattern0_unverified_incrementing_write_with_reply;
                return std::vector<uint8_t>(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
            },
            [] {
                auto pattern = test_pattern1_incrementing_read;
                return std::vector<uint8_t>(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
            },
            [] {
                auto pattern =
                    test_pattern2_unverified_incrementing_write_with_reply_with_spacewire_addresses;
                return std::vector<uint8_t>(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
            },
            [] {
                auto pattern =
                    test_pattern3_incrementing_read_with_spacewire_addresses;
                return std::vector<uint8_t>(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
            },
            [] {
                auto pattern = test_pattern4_rmw;
                return std::vector<uint8_t>(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
            },
            [] {
                auto pattern = test_pattern5_rmw_with_spacewire_addresses;
                return std::vector<uint8_t>(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
            }),
        testing::Values(RMAP_NODE_COMMAND_RECEIVED_BY_INITIATOR)));

INSTANTIATE_TEST_SUITE_P(
    IncompleteHeader,
    IncomingToInitiatorRejectParams,
    testing::Combine(
        testing::Values(
            [] {
                auto pattern = test_pattern0_expected_write_reply;
                std::vector<uint8_t> incoming_packet(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
                incoming_packet.resize(
                    rmap_calculate_header_size(incoming_packet.data()) - 1);
                return incoming_packet;
            },
            [] {
                auto pattern = test_pattern0_expected_write_reply;
                std::vector<uint8_t> incoming_packet(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
                /* Only target logical address and protocol. */
                incoming_packet.resize(2);
                return incoming_packet;
            },
            [] {
                auto pattern = test_pattern0_expected_write_reply;
                std::vector<uint8_t> incoming_packet(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
                /* Only target logical address. */
                incoming_packet.resize(1);
                return incoming_packet;
            }),
        testing::Values(RMAP_INCOMPLETE_HEADER)));

INSTANTIATE_TEST_SUITE_P(
    HeaderCrcError,
    IncomingToInitiatorRejectParams,
    testing::Combine(
        testing::Values(
            [] {
                auto pattern = test_pattern0_expected_write_reply;
                std::vector<uint8_t> incoming_packet(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
                /* Flip a bit in the status field. */
                incoming_packet.at(3) ^= 1;
                return incoming_packet;
            },
            [] {
                auto pattern = test_pattern0_expected_write_reply;
                std::vector<uint8_t> incoming_packet(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
                const size_t header_size =
                    rmap_calculate_header_size(incoming_packet.data());
                /* Flip a bit in the CRC field. */
                incoming_packet.at(header_size - 1) ^= 1;
                return incoming_packet;
            }),
        testing::Values(RMAP_HEADER_CRC_ERROR)));

INSTANTIATE_TEST_SUITE_P(
    InvalidProtocol,
    IncomingToInitiatorRejectParams,
    testing::Combine(
        testing::Values(
            [] {
                auto pattern = test_pattern0_expected_write_reply;
                std::vector<uint8_t> incoming_packet(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
                /* Set non-RMAP protocol. */
                incoming_packet.at(1) = 0x00;
                rmap_calculate_and_set_header_crc(incoming_packet.data());
                return incoming_packet;
            },
            [] {
                auto pattern = test_pattern0_expected_write_reply;
                std::vector<uint8_t> incoming_packet(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
                /* Set non-RMAP protocol. */
                incoming_packet.at(1) = 0x02;
                rmap_calculate_and_set_header_crc(incoming_packet.data());
                return incoming_packet;
            }),
        testing::Values(RMAP_NO_RMAP_PROTOCOL)));

INSTANTIATE_TEST_SUITE_P(
    PacketError,
    IncomingToInitiatorRejectParams,
    testing::Combine(
        testing::Values(
            [] {
                auto pattern = test_pattern0_expected_write_reply;
                std::vector<uint8_t> incoming_packet(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
                /* Set reserved bit in packet type field. */
                incoming_packet.at(2) |= 1 << 7;
                rmap_calculate_and_set_header_crc(incoming_packet.data());
                return incoming_packet;
            },
            [] {
                auto pattern = test_pattern1_expected_read_reply;
                std::vector<uint8_t> incoming_packet(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
                const uint8_t instruction =
                    rmap_get_instruction(incoming_packet.data());
                /* Set verify bit and clear increment bit to create an invalid
                 * command code (read, verified, non-incrementing, with reply).
                 */
                rmap_set_instruction(
                    incoming_packet.data(),
                    (instruction | RMAP_COMMAND_CODE_VERIFY << 2) &
                        ~(RMAP_COMMAND_CODE_INCREMENT << 2));
                rmap_calculate_and_set_header_crc(incoming_packet.data());
                return incoming_packet;
            },
            [] {
                auto pattern = test_pattern0_expected_write_reply;
                std::vector<uint8_t> incoming_packet(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
                const uint8_t instruction =
                    rmap_get_instruction(incoming_packet.data());
                /* Clear reply bit to create a reply which should not have been
                 * generated based on its command code.
                 */
                rmap_set_instruction(
                    incoming_packet.data(),
                    instruction & ~(RMAP_COMMAND_CODE_REPLY << 2));
                rmap_calculate_and_set_header_crc(incoming_packet.data());
                return incoming_packet;
            }),
        testing::Values(RMAP_NODE_PACKET_ERROR)));

INSTANTIATE_TEST_SUITE_P(
    InvalidReply,
    IncomingToInitiatorRejectParams,
    testing::Combine(
        testing::Values(
            [] {
                auto pattern = test_pattern4_expected_rmw_reply;
                std::vector<uint8_t> incoming_packet(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
                rmap_set_data_length(incoming_packet.data(), 5);
                rmap_calculate_and_set_header_crc(incoming_packet.data());
                const size_t data_offset =
                    rmap_calculate_header_size(incoming_packet.data());
                incoming_packet.resize(data_offset + 5 + 1);
                incoming_packet.back() =
                    rmap_crc_calculate(incoming_packet.data() + data_offset, 5);
                return incoming_packet;
            },
            [] {
                auto pattern = test_pattern1_expected_read_reply;
                std::vector<uint8_t> incoming_packet(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
                /* One byte too small. */
                incoming_packet.pop_back();
                return incoming_packet;
            },
            [] {
                auto pattern = test_pattern1_expected_read_reply;
                std::vector<uint8_t> incoming_packet(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
                /* One byte too big. */
                incoming_packet.push_back(0xDA);
                return incoming_packet;
            },
            [] {
                auto pattern = test_pattern1_expected_read_reply;
                std::vector<uint8_t> incoming_packet(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
                /* Flip a bit in data field. */
                incoming_packet.at(
                    rmap_calculate_header_size(incoming_packet.data())) ^= 1;
                return incoming_packet;
            },
            [] {
                auto pattern = test_pattern1_expected_read_reply;
                std::vector<uint8_t> incoming_packet(
                    pattern.data.begin() + pattern.header_offset,
                    pattern.data.end());
                /* Flip a bit in data CRC field. */
                incoming_packet.back() ^= 1;
                return incoming_packet;
            }),
        testing::Values(RMAP_NODE_INVALID_REPLY)));
