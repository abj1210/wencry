#include "hashmaster.h"
#include "hashbuffer.h"
#include "testutil.h"
#include "gtest/gtest.h"

Hashmaster *htest;

TEST(Testsha256, testsha256_1) {
  char s1[] = "abcd";
  unsigned char hash[htest->gethlen()], hashcmp[htest->gethlen()];
  htest->getStringHash((unsigned char *)s1, 4, hash);
  gethex("88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589", hashcmp);
  EXPECT_TRUE(cmpstr(hash, hashcmp, htest->gethlen()));
}

TEST(Testsha256, testsha256_2) {
  char s1[] =
      "asdsfgfgdfgdfgdfgdfgfdggdssssssdddddddddddddwdfrgthyjghgfdfefsfefesfesf";
  unsigned char hash[htest->gethlen()], hashcmp[htest->gethlen()];
  htest->getStringHash((unsigned char *)s1, strlen(s1), hash);
  gethex("1f3b3dad2bcb709dc143192f8d84be59e7d722619b3d3eb96be9a5a53e279d7d", hashcmp);
  EXPECT_TRUE(cmpstr(hash, hashcmp, htest->gethlen()));
}

TEST(Testsha256, testsha256_3) {
  FILE *fp = genfile("abcd");
  unsigned char hash[htest->gethlen()], hashcmp[htest->gethlen()];
  buffer64 * buf = new filebuffer64(fp); 
  htest->getFileHash(buf, hash);
  gethex("88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589", hashcmp);
  EXPECT_TRUE(cmpstr(hash, hashcmp, htest->gethlen()));
  fclose(fp);
}

int main(int argc, char **argv) {
  HashFactory hf;
  htest = hf.getHasher(HashFactory::HASH_TYPE::SHA256);
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}