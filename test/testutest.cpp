#include "testutil.h"
#include "gtest/gtest.h"
TEST(Testutest, testhex) {
  unsigned char out[100];
  gethex("2500af7c", out);
  EXPECT_EQ(0x25, (int)out[0]);
  EXPECT_EQ(0x00, (int)out[1]);
  EXPECT_EQ(0xaf, (int)out[2]);
  EXPECT_EQ(0x7c, (int)out[3]);
  gethex("AABBCCDD", out);
  EXPECT_EQ(0xAA, (int)out[0]);
  EXPECT_EQ(0xBB, (int)out[1]);
  EXPECT_EQ(0xCC, (int)out[2]);
  EXPECT_EQ(0xDD, (int)out[3]);
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}