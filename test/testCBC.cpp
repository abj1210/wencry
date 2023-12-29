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
char res[] = "79ec62d5292788eeda7a63769cfbfe1a7f22ab8059086770b2047773cb4049893"
             "2d7b02f07fb0812a04705535b9df6534f07db6c8bf9b97ee98d9bc69c4397d3";

TEST(TestCBC, testCBC1) {
  unsigned char block[64], blcmp[64];
  memcpy(block, str, 64);
  AesCBC CBCtest(key, iv);
  for (int i = 0; i < 4; i++)
    CBCtest.getencry(block + (16 * i));
  gethex(res, blcmp);
  EXPECT_TRUE(cmpstr(block, blcmp, 64));
}
TEST(TestCBC, testCBC2) {
  unsigned char block[64], blcmp[64];
  memcpy(block, str, 64);
  memcpy(blcmp, str, 64);
  AesCBC CBCtest(key, iv);
  for (int i = 0; i < 4; i++)
    CBCtest.getencry(block + (16 * i));
  CBCtest.resetIV();
  for (int i = 0; i < 4; i++)
    CBCtest.getdecry(block + (16 * i));
  EXPECT_TRUE(cmpstr(block, blcmp, 64));
}
TEST(TestCBC, testCBC3) {
  unsigned char block[64], blcmp[64];
  memcpy(block, str, 64);
  memcpy(blcmp, str, 64);
  AesCBC CBCt1(key, iv);
  AesCBC CBCt2(key, iv2);
  for (int i = 0; i < 4; i++)
    CBCt1.getencry(block + (16 * i));
  for (int i = 0; i < 4; i++)
    CBCt2.getencry(blcmp + (16 * i));
  EXPECT_FALSE(cmpstr(block, blcmp, 64));
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}