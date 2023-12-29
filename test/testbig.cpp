#include "test.h"
#include "gtest/gtest.h"

TEST(Testbig, testb1) { EXPECT_EQ(1, makeBigTest(0)); }
TEST(Testbig, testb2) { EXPECT_EQ(1, makeBigTest(3)); }

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}