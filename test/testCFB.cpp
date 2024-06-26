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
  AesFactory af(key, iv);
  Aesmode *AEStest = af.createCryMaster(true, 3);
  for (int i = 0; i < 4; i++)
    AEStest->runcry(block + (16 * i));
  gethex(res, blcmp);
  EXPECT_TRUE(cmpstr(block, blcmp, 64));
}
TEST(TestCFB, testCFB2) {
  unsigned char block[64], blcmp[64];
  memcpy(block, str, 64);
  memcpy(blcmp, str, 64);
  AesFactory af(key, iv);
  Aesmode * AEStest = af.createCryMaster(true, 3),
          * AESdecrypt = af.createCryMaster(false, 3);
  for (int i = 0; i < 4; i++)
    AEStest->runcry(block + (16 * i));
  for (int i = 0; i < 4; i++)
    AESdecrypt->runcry(block + (16 * i));
  EXPECT_TRUE(cmpstr(block, blcmp, 64));
}
TEST(TestCFB, testCFB3) {
  unsigned char block[64], blcmp[64];
  memcpy(block, str, 64);
  memcpy(blcmp, str, 64);
  AesFactory af1(key, iv);
  AesFactory af2(key, iv2);
  Aesmode * AESt1 = af1.createCryMaster(true, 3);
  Aesmode * AESt2 = af2.createCryMaster(true, 3);
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