#include "aes.h"
#include "testutil.h"
#include "gtest/gtest.h"

TEST(Testaes, testres) {
  unsigned char key[16] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                           '0', '1', '2', '3', '4', '5', '6', '7'};
  encryaes etest(key);
  unsigned char block[] = "I'm a test msg.";
  unsigned char aescmp[16];
  etest.runaes_128bit(block);
  gethex("e3481e03f1a1a6ccdf72a155cd88732b", aescmp);
  EXPECT_TRUE(cmpstr(block, aescmp, 16));
}
TEST(Testaes, testround1) {
  unsigned char key[16] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                           '0', '1', '2', '3', '4', '5', '6', '7'};
  encryaes etest(key);
  decryaes dtest(key);
  unsigned char block[] = "I'm a test msg.";
  unsigned char aescmp[] = "I'm a test msg.";
  etest.runaes_128bit(block);
  dtest.runaes_128bit(block);
  EXPECT_TRUE(cmpstr(block, aescmp, 16));
}
TEST(Testaes, testround2) {
  unsigned char key[16] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                           '0', '1', '2', '3', '4', '5', '6', '7'};
  encryaes etest(key);
  key[0] = 'A';
  decryaes dtest(key);
  unsigned char block[] = "I'm a test msg.";
  unsigned char aescmp[] = "I'm a test msg.";
  etest.runaes_128bit(block);
  dtest.runaes_128bit(block);
  EXPECT_FALSE(cmpstr(block, aescmp, 16));
}
int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}