#include "test.h"
#include "gtest/gtest.h"

char str[] =
    "ababrteyuioiuetwreyuioyjfhtdfdfsdfsdfdsfgfhtfhtfhfyhfthdrhdgsrfseaba"
    "brteyuioiuetwreyuioyjfhtdfdfsdfsdfdsfgfhtfhtfhfyhfthdrhdgsrfse";

TEST(Testsmode, testsm1) { EXPECT_EQ(1, makeFullTest(str, 1)); }

TEST(Testsmode, testsm2) { EXPECT_EQ(1, makeFullTest(str, 2)); }

TEST(Testsmode, testsm3) { EXPECT_EQ(1, makeFullTest(str, 3)); }

TEST(Testsmode, testsm4) { EXPECT_EQ(1, makeFullTest(str, 4)); }

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}