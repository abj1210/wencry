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
  AesFactory af(key, iv);
  Aesmode *AEStest = af.createCryMaster(true, 1);
  for (int i = 0; i < 4; i++)
    AEStest->runcry(block + (16 * i));
  gethex(res, blcmp);
  EXPECT_TRUE(cmpstr(block, blcmp, 64));
}
TEST(TestCBC, testCBC2) {
  unsigned char block[64], blcmp[64];
  memcpy(block, str, 64);
  memcpy(blcmp, str, 64);
  AesFactory af(key, iv);
  Aesmode * AEStest = af.createCryMaster(true, 1),
          * AESdecrypt = af.createCryMaster(false, 1);
  for (int i = 0; i < 4; i++)
    AEStest->runcry(block + (16 * i));
  for (int i = 0; i < 4; i++)
    AESdecrypt->runcry(block + (16 * i));
  EXPECT_TRUE(cmpstr(block, blcmp, 64));
}
TEST(TestCBC, testCBC3) {
  unsigned char block[64], blcmp[64];
  memcpy(block, str, 64);
  memcpy(blcmp, str, 64);
  AesFactory af1(key, iv);
  AesFactory af2(key, iv2);
  Aesmode * AESt1 = af1.createCryMaster(true, 1);
  Aesmode * AESt2 = af2.createCryMaster(true, 1);
  for (int i = 0; i < 4; i++)
    AESt1->runcry(block + (16 * i));
  for (int i = 0; i < 4; i++)
    AESt2->runcry(blcmp + (16 * i));
  EXPECT_FALSE(cmpstr(block, blcmp, 64));
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}