#ifndef RMAP_SHIM_H
#define RMAP_SHIM_H

#include "rmap.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Shims which use int instead of enum for packet type, in order to allow
 * testing behaviour for undefined packet types.
 *
 * Assigning an undefined value to an enum object is undefined behaviour in C++
 * but is defined behaviour in C as long as the value is within the underlying
 * integer type of the enum.
 */

enum rmap_status rmap_shim_initialize_header(
    void *header,
    size_t max_size,
    int packet_type,
    int command_code,
    size_t reply_address_unpadded_size);

enum rmap_status rmap_shim_initialize_header_before(
    size_t *header_offset,
    void *raw,
    size_t data_offset,
    int packet_type,
    int command_code,
    size_t reply_address_unpadded_size);

#ifdef __cplusplus
}
#endif

#endif /* RMAP_SHIM_H */
