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
char res[] = "7f268e32fa3589c5b37fa0917e21f3267f268e32fa3589c5b37fa0917e21f3267"
             "f268e32fa3589c5b37fa0917e21f326e3481e03f1a1a6ccdf72a155cd88732b";

TEST(TestECB, testECB1) {
  unsigned char block[64], blcmp[64];
  memcpy(block, str, 64);
  AesECB ECBtest(key, iv);
  for (int i = 0; i < 4; i++)
    ECBtest.getencry(block + (16 * i));
  gethex(res, blcmp);
  EXPECT_TRUE(cmpstr(block, blcmp, 64));
}

TEST(TestECB, testECB2) {
  unsigned char block[64], blcmp[64];
  memcpy(block, str, 64);
  memcpy(blcmp, str, 64);
  AesECB ECBtest(key, iv);
  for (int i = 0; i < 4; i++)
    ECBtest.getencry(block + (16 * i));
  ECBtest.resetIV();
  for (int i = 0; i < 4; i++)
    ECBtest.getdecry(block + (16 * i));
  EXPECT_TRUE(cmpstr(block, blcmp, 64));
}

TEST(TestECB, testECB3) {
  unsigned char block[64], blcmp[64];
  memcpy(block, str, 64);
  memcpy(blcmp, str, 64);
  AesECB ECBt1(key, iv);
  AesECB ECBt2(key, iv2);
  for (int i = 0; i < 4; i++)
    ECBt1.getencry(block + (16 * i));
  for (int i = 0; i < 4; i++)
    ECBt2.getencry(blcmp + (16 * i));
  EXPECT_TRUE(cmpstr(block, blcmp, 64));
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}