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
char res[] = "932f13241d607db9e194a270d42aa03f8da0c3910604044ec875e9f23f9b45f57"
             "441b64d91ecf123f62086ff139e1ce13f7a44bd758b2bda632a40c9e5afb8b6";

TEST(TestCFB, testCFB1) {
  unsigned char block[64], blcmp[64];
  memcpy(block, str, 64);
  AesCFB CFBtest(key, iv);
  for (int i = 0; i < 4; i++)
    CFBtest.getencry(block + (16 * i));
  gethex(res, blcmp);
  EXPECT_TRUE(cmpstr(block, blcmp, 64));
}
TEST(TestCFB, testCFB2) {
  unsigned char block[64], blcmp[64];
  memcpy(block, str, 64);
  memcpy(blcmp, str, 64);
  AesCFB CFBtest(key, iv);
  for (int i = 0; i < 4; i++)
    CFBtest.getencry(block + (16 * i));
  CFBtest.resetIV();
  for (int i = 0; i < 4; i++)
    CFBtest.getdecry(block + (16 * i));
  EXPECT_TRUE(cmpstr(block, blcmp, 64));
}
TEST(TestCFB, testCFB3) {
  unsigned char block[64], blcmp[64];
  memcpy(block, str, 64);
  memcpy(blcmp, str, 64);
  AesCFB CFBt1(key, iv);
  AesCFB CFBt2(key, iv2);
  for (int i = 0; i < 4; i++)
    CFBt1.getencry(block + (16 * i));
  for (int i = 0; i < 4; i++)
    CFBt2.getencry(blcmp + (16 * i));
  EXPECT_FALSE(cmpstr(block, blcmp, 64));
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}