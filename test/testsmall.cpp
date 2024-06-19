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

TEST(Testsmall, roundtest) {
  srand(time(NULL));
  char buf[257];
  buf[256] = '\0';
  for (int i = 0; i < 256; i++) {
    printf("Test num : %d\n", i);
    for(int j = 0; j < 256; j++) {
      buf[j] = rand();
    }
    EXPECT_EQ(1, makeFullTest(buf));
  }
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}