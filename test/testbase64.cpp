#include "base64.h"
#include "testutil.h"
#include "gtest/gtest.h"

TEST(Testbase64, testhextob64) {
  unsigned char str[] = "abcdefg";
  unsigned char b64[13];
  unsigned char out[] = "YWJjZGVmZw==";
  hexToBase64(str, 7, b64);
  EXPECT_TRUE(cmpstr(b64, out, 13));
}

TEST(Testbase64, testb64tohex) {
  unsigned char str[9];
  str[8] = 0;
  unsigned char b64[] = "YWJjZDEyMzQ=";
  unsigned char out[] = "abcd1234";
  base64ToHex(b64, 12, str);
  EXPECT_TRUE(cmpstr(str, out, 9));
}
TEST(Testbase64, testround1) {
  unsigned char str[] = "I'm a test msg.";
  unsigned char out[21];
  unsigned char cmp[16];
  cmp[15] = 0;
  hexToBase64(str, 15, out);
  base64ToHex(out, 20, cmp);
  EXPECT_TRUE(cmpstr(str, cmp, 16));
}

TEST(Testbase64, testhex2remainder) {
  // 输入 2 字节(余数为 2),应编码为 4 字符且带 1 个 '=' 填充。
  unsigned char out[5] = {0};
  hexToBase64((const unsigned char *)"ab", 2, out);
  EXPECT_TRUE(cmpstr(out, (const unsigned char *)"YWI=", 5));
}

TEST(Testbase64, testvalid) {
  EXPECT_FALSE(isValidBase64((const u8_t *)"!!!!", 4));
  EXPECT_FALSE(isValidBase64((const u8_t *)"A===", 4));
  EXPECT_FALSE(isValidBase64((const u8_t *)"A=B=", 4));
  EXPECT_TRUE(isValidBase64((const u8_t *)"ABEiM0RVZneImaq7zN3u/w==", 24));
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
