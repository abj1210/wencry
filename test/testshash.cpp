#include "test.h"
#include "gtest/gtest.h"

char str[] =
    "ababrteyuioiuetwreyuioyjfhtdfdfsdfsdfdsfgfhtfhtfhfyhfthdrhdgsrfseaba"
    "brteyuioiuetwreyuioyjfhtdfdfsdfsdfdsfgfhtfhtfhfyhfthdrhdgsrfse";

TEST(Testsmode, testsha1)
{
  EXPECT_EQ(1, makeFullTest(str, 0x00));
}
TEST(Testsmode, testmd5)
{
  EXPECT_EQ(1, makeFullTest(str, 0x10));
}
TEST(Testsmode, testsha256)
{
  EXPECT_EQ(1, makeFullTest(str, 0x20));
}

int main(int argc, char **argv)
{
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}