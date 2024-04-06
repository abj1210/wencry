#include "test.h"
#include "gtest/gtest.h"

TEST(Testbig, testb1) { EXPECT_EQ(makeBigTest(0, 1), 1); }
TEST(Testbig, testb2) { EXPECT_EQ(makeBigTest(3, 1), 1); }

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}