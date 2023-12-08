#include "test.h"
#include "gtest/gtest.h"

TEST(Testsmall2, tests2) {
  EXPECT_EQ(
      1,
      makeFullTest(
          "ababrteyuioiuetwreyuioyjfhtdfdfsdfsdfdsfgfhtfhtfhfyhfthdrhdgsrfseaba"
          "brteyuioiuetwreyuioyjfhtdfdfsdfsdfdsfgfhtfhtfhfyhfthdrhdgsrf"));
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}