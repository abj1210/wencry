#include "test.h"
#include "gtest/gtest.h"

TEST(Testsmall1, tests1) {
  EXPECT_EQ(
      1,
      makeFullTest(
          "ababrteyuioiuetwreyuioyjfhtdfdfsdfsdfdsfgfhtfhtfhfyhfthdrhdgsrfseaba"
          "brteyuioiuetwreyuioyjfhtdfdfsdfsdfdsfgfhtfhtfhfyhfthdrhdgsrfse"));
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}