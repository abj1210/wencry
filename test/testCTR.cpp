#include "aesmode.h"
#include "testutil.h"
#include "gtest/gtest.h"

unsigned char key[16] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                         '0', '1', '2', '3', '4', '5', '6', '7'};
unsigned char iv[20] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                        '0', '1', '2', '3', '4', '5', '6', '7'};
unsigned char iv2[20] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                         '0', '1', '2', '3', '4', '5', '6', '7'};
unsigned char str[] =
    "I'm a test msg. I'm a test msg. I'm a test msg. I'm a test msg.";
char res[] = "932f13241d607db9e194a270d42aa03ffc8e35ff18aab86a97d679b134dd3c500"
             "08312aadaa1ec68f08b5d2177994d2c27a9db77f7252098e1dd01f8d3fba78e";

TEST(TestCTR, testCTR1) {
  unsigned char block[64], blcmp[64];
  memcpy(block, str, 64);
  AesCTR CTRtest(key, iv);
  for (int i = 0; i < 4; i++)
    CTRtest.getencry(block + (16 * i));
  gethex(res, blcmp);
  EXPECT_TRUE(cmpstr(block, blcmp, 64));
}
TEST(TestCTR, testCTR2) {
  unsigned char block[64], blcmp[64];
  memcpy(block, str, 64);
  memcpy(blcmp, str, 64);
  AesCTR CTRtest(key, iv);
  for (int i = 0; i < 4; i++)
    CTRtest.getencry(block + (16 * i));
  CTRtest.resetIV();
  for (int i = 0; i < 4; i++)
    CTRtest.getdecry(block + (16 * i));
  EXPECT_TRUE(cmpstr(block, blcmp, 64));
}
TEST(TestCTR, testCTR3) {
  unsigned char block[64], blcmp[64];
  memcpy(block, str, 64);
  memcpy(blcmp, str, 64);
  AesCTR CTRt1(key, iv);
  AesCTR CTRt2(key, iv2);
  for (int i = 0; i < 4; i++)
    CTRt1.getencry(block + (16 * i));
  for (int i = 0; i < 4; i++)
    CTRt2.getencry(blcmp + (16 * i));
  EXPECT_FALSE(cmpstr(block, blcmp, 64));
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}