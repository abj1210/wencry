#include "gtest/gtest.h"
#include "test.h"

TEST(Testsmall1, tests1){
  EXPECT_EQ(1, makeFullTest(
    "ababrteyuioiuetwreyuioyjfhtdfdfsdfsdfdsfgfhtfhtfhfyhfthdrhdgsrfseababrteyuioiuetwreyuioyjfhtdfdfsdfsdfdsfgfhtfhtfhfyhfthdrhdgsrfse"
  ));
}

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}