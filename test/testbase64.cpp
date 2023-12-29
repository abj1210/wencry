#include "base64.h"
#include "testutil.h"
#include "gtest/gtest.h"

TEST(Testbase64, testhextob64) {
  unsigned char str[] = "abcdefg";
  unsigned char b64[13];
  unsigned char out[] = "YWJjZGVmZw==";
  hex_to_base64(str, 7, b64);
  EXPECT_TRUE(cmpstr(b64, out, 13));
}

TEST(Testbase64, testb64tohex) {
  unsigned char str[9];
  str[8] = 0;
  unsigned char b64[] = "YWJjZDEyMzQ=";
  unsigned char out[] = "abcd1234";
  base64_to_hex(b64, 12, str);
  EXPECT_TRUE(cmpstr(str, out, 9));
}
TEST(Testbase64, testround1) {
  unsigned char str[] = "I'm a test msg.";
  unsigned char out[21];
  unsigned char cmp[16];
  cmp[15] = 0;
  hex_to_base64(str, 15, out);
  base64_to_hex(out, 20, cmp);
  EXPECT_TRUE(cmpstr(str, cmp, 16));
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}