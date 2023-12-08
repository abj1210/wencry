#include "test.h"
#include "gtest/gtest.h"

TEST(Testspeed, testsp) { EXPECT_EQ(1, makeSpeedTest()); }

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}