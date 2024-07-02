#include "rmap.h"

/* Custom non-table-based (slow) CRC. */
uint8_t rmap_crc_calculate(const void *const data, const size_t data_size)
{
    uint8_t crc;

    /* x^8 + x^2 + x^1 + x^0 */
    const uint8_t polynomial_reversed = 0xE0;
    const unsigned char *const data_bytes = data;
    crc = 0;
    for (size_t i = 0; i < data_size; ++i) {
        crc ^= data_bytes[i];
        for (int j = 0; j < 8; ++j) {
            if (crc & 1) {
                crc = (crc >> 1) ^ polynomial_reversed;
            } else {
                crc >>= 1;
            }
        }
    }

    return crc;
}
