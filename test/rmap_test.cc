#include <gtest/gtest.h>

extern "C" {
#include "rmap.h"
}

TEST(RmapCrcCalculate, ZeroesInDataGivesZeroCrc)
{
  unsigned char data[17] = {};

  EXPECT_EQ(rmap_crc_calculate(data, sizeof(data)), 0x00);
}
