#include "test.h"
#include "gtest/gtest.h"
#include <iostream>

TEST(Testspeed, testsp) {
  double mbs = makeSpeedTest(1);
  std::cout << "AES-CBC encrypt throughput: " << mbs << " MB/s\n";
  EXPECT_GE(mbs, 5.0);
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}