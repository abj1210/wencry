#include "hashmaster.h"
#include "hashbuffer.h"
#include "testutil.h"
#include "gtest/gtest.h"

Hashmaster *htest;

TEST(Testmd5, testmd5_1) {
  char s1[] = "abcd";
  unsigned char hash[htest->gethlen()], hashcmp[htest->gethlen()];
  htest->getStringHash((unsigned char *)s1, 4, hash);
  gethex("E2FC714C4727EE9395F324CD2E7F331F", hashcmp);
  EXPECT_TRUE(cmpstr(hash, hashcmp, htest->gethlen()));
}

TEST(Testmd5, testmd5_2) {
  char s1[] =
      "asdsfgfgdfgdfgdfgdfgfdggdssssssdddddddddddddwdfrgthyjghgfdfefsfefesfesf";
  unsigned char hash[htest->gethlen()], hashcmp[htest->gethlen()];
  htest->getStringHash((unsigned char *)s1, strlen(s1), hash);
  gethex("A3633338CD8C1462E58B03EF3158C48F", hashcmp);
  EXPECT_TRUE(cmpstr(hash, hashcmp, htest->gethlen()));
}

TEST(Testmd5, testmd5_3) {
  FILE *fp = genfile("abcd");
  unsigned char hash[htest->gethlen()], hashcmp[htest->gethlen()];
  buffer64 * buf = new filebuffer64(fp); 
  htest->getFileHash(buf, hash);
  gethex("E2FC714C4727EE9395F324CD2E7F331F", hashcmp);
  EXPECT_TRUE(cmpstr(hash, hashcmp, htest->gethlen()));
  fclose(fp);
}

int main(int argc, char **argv) {
  HashFactory hf;
  htest = hf.getHasher(HashFactory::HASH_TYPE::MD5);
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}