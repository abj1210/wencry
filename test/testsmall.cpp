#include "test.h"
#include "gtest/gtest.h"

TEST(Testsmall, tests1) {
  EXPECT_EQ(
      1,
      makeFullTest(
          "ababrteyuioiuetwreyuioyjfhtdfdfsdfsdfdsfgfhtfhtfhfyhfthdrhdgsrfseaba"
          "brteyuioiuetwreyuioyjfhtdfdfsdfsdfdsfgfhtfhtfhfyhfthdrhdgsrfse"));
}

TEST(Testsmall, tests2) {
  EXPECT_EQ(
      1,
      makeFullTest(
          "ababrteyuioiuetwreyuioyjfhtdfdfsdfsdfdsfgfhtfhtfhfyhfthdrhdgsrfseaba"
          "brteyuioiuetwreyuioyjfhtdfdfsdfsdfdsfgfhtfhtfhfyhfthdrhdgsrf"));
}

TEST(Testsmall, randomtest) {
  srand(time(NULL));
  char buf[257];
  buf[128] = '\0';
  for(int j = 0; j < 128; j++) 
    buf[j] = rand()%26 + 'A';
  EXPECT_EQ(1, makeFullTest(buf));
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}