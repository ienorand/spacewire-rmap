#include "rmap_shim.h"

enum rmap_status rmap_shim_initialize_header(
    void *const header,
    const size_t max_size,
    const int packet_type,
    const int command_code,
    const size_t reply_address_unpadded_size)
{
    return rmap_initialize_header(
        header,
        max_size,
        packet_type,
        command_code,
        reply_address_unpadded_size);
}

enum rmap_status rmap_shim_initialize_header_before(
    size_t *const header_offset,
    void *const raw,
    const size_t data_offset,
    const int packet_type,
    const int command_code,
    const size_t reply_address_unpadded_size)
{
    return rmap_initialize_header_before(
        header_offset,
        raw,
        data_offset,
        packet_type,
        command_code,
        reply_address_unpadded_size);
}
