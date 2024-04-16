#include "test.h"
#include "gtest/gtest.h"

char str[] =
    "ababrteyuioiuetwreyuioyjfhtdfdfsdfsdfdsfgfhtfhtfhfyhfthdrhdgsrfseaba"
    "brteyuioiuetwreyuioyjfhtdfdfsdfsdfdsfgfhtfhtfhfyhfthdrhdgsrfse";

TEST(Testsmode, testsm1) { EXPECT_EQ(1, makeFullTest(str, 0x11)); }

TEST(Testsmode, testsm2) { EXPECT_EQ(1, makeFullTest(str, 0x12)); }

TEST(Testsmode, testsm3) { EXPECT_EQ(1, makeFullTest(str, 0x13)); }

TEST(Testsmode, testsm4) { EXPECT_EQ(1, makeFullTest(str, 0x14)); }

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}