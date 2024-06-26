#include "test.h"
#include "gtest/gtest.h"

char str[] =
    "ababrteyuioiuetwreyuioyjfhtdfdfsdfsdfdsfgfhtfhtfhfyhfthdrhdgsrfseaba"
    "brteyuioiuetwreyuioyjfhtdfdfsdfsdfdsfgfhtfhtfhfyhfthdrhdgsrfse";

TEST(Testsmode, testsha1) { 
  for(int i = 0; i < 5 ; i++) 
    EXPECT_EQ(1, makeFullTest(str, 0x00+i));
}
TEST(Testsmode, testmd5) { 
  for(int i = 0; i < 5 ; i++) 
    EXPECT_EQ(1, makeFullTest(str, 0x10+i));
}
TEST(Testsmode, testsha256) { 
  for(int i = 0; i < 5 ; i++) 
    EXPECT_EQ(1, makeFullTest(str, 0x20+i));
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}