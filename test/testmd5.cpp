#include "hashmaster.h"
#include "testutil.h"
#include "gtest/gtest.h"

Hashmaster *htest;

TEST(Testmd5, testmd5_1) {
  char s1[] = "abcd";
  unsigned char hash[16], hashcmp[16];
  htest->getStringHash((unsigned char *)s1, 4, hash);
  gethex("E2FC714C4727EE9395F324CD2E7F331F", hashcmp);
  EXPECT_TRUE(cmpstr(hash, hashcmp, 16));
}

TEST(Testmd5, testmd5_2) {
  char s1[] =
      "asdsfgfgdfgdfgdfgdfgfdggdssssssdddddddddddddwdfrgthyjghgfdfefsfefesfesf";
  unsigned char hash[16], hashcmp[16];
  htest->getStringHash((unsigned char *)s1, strlen(s1), hash);
  gethex("A3633338CD8C1462E58B03EF3158C48F", hashcmp);
  EXPECT_TRUE(cmpstr(hash, hashcmp, 16));
}

TEST(Testmd5, testmd5_3) {
  FILE *fp = genfile("abcd");
  unsigned char hash[16], hashcmp[16];
  htest->getFileHash(fp, hash);
  gethex("E2FC714C4727EE9395F324CD2E7F331F", hashcmp);
  EXPECT_TRUE(cmpstr(hash, hashcmp, 16));
  fclose(fp);
}

int main(int argc, char **argv) {
  HashFactory hf;
  htest = hf.getHasher(HashFactory::HASH_TYPE::MD5);
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}