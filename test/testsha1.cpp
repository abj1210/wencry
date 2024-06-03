#include "hashmaster.h"
#include "hashbuffer.h"
#include "testutil.h"
#include "gtest/gtest.h"

Hashmaster *htest;

TEST(Testsha1, testsha1_1) {
  char s1[] = "abcd";
  unsigned char hash[20], hashcmp[20];
  htest->getStringHash((unsigned char *)s1, 4, hash);
  gethex("81fe8bfe87576c3ecb22426f8e57847382917acf", hashcmp);
  EXPECT_TRUE(cmpstr(hash, hashcmp, 20));
}

TEST(Testsha1, testsha1_2) {
  char s1[] =
      "asdsfgfgdfgdfgdfgdfgfdggdssssssdddddddddddddwdfrgthyjghgfdfefsfefesfesf";
  unsigned char hash[20], hashcmp[20];
  htest->getStringHash((unsigned char *)s1, strlen(s1), hash);
  gethex("fd15bb59b548b867c5abe2460d93be2f44a6b1cf", hashcmp);
  EXPECT_TRUE(cmpstr(hash, hashcmp, 20));
}

TEST(Testsha1, testsha1_3) {
  FILE *fp = genfile("abcd");
  unsigned char hash[20], hashcmp[20];
  buffer64 * buf = new filebuffer64(fp); 
  htest->getFileHash(buf, hash);
  gethex("81fe8bfe87576c3ecb22426f8e57847382917acf", hashcmp);
  EXPECT_TRUE(cmpstr(hash, hashcmp, 20));
  fclose(fp);
}

int main(int argc, char **argv) {
  HashFactory hf;
  htest = hf.getHasher(HashFactory::HASH_TYPE::SHA1);
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}