#include "hashmaster.h"
#include "testutil.h"
#include "gtest/gtest.h"
#define TNAME Testsha256
#define TSNAME(tname) TNAME_##tname
Hashmaster *htest;

TEST(TNAME, TSNAME(1)) {
  char s1[] = "abcd";
  unsigned char hash[htest->gethlen()], hashcmp[htest->gethlen()];
  htest->getStringHash((unsigned char *)s1, 4, hash);
  gethex("88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589", hashcmp);
  EXPECT_TRUE(cmpstr(hash, hashcmp, htest->gethlen()));
}

TEST(TNAME, TSNAME(2)) {
  char s1[] =
      "asdsfgfgdfgdfgdfgdfgfdggdssssssdddddddddddddwdfrgthyjghgfdfefsfefesfesf";
  unsigned char hash[htest->gethlen()], hashcmp[htest->gethlen()];
  htest->getStringHash((unsigned char *)s1, strlen(s1), hash);
  gethex("1f3b3dad2bcb709dc143192f8d84be59e7d722619b3d3eb96be9a5a53e279d7d", hashcmp);
  EXPECT_TRUE(cmpstr(hash, hashcmp, htest->gethlen()));
}

TEST(TNAME, TSNAME(3)) {
  FILE *fp = genfile("abcd");
  unsigned char buf[64] = {0};
  size_t n = fread(buf, 1, sizeof(buf), fp);
  unsigned char hash[htest->gethlen()], hashcmp[htest->gethlen()];
  htest->getStringHash(buf, (unsigned int)n, hash);
  gethex("88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589", hashcmp);
  EXPECT_TRUE(cmpstr(hash, hashcmp, htest->gethlen()));
  fclose(fp);
}

TEST(TNAME, TSNAME(4)) {
  char s1[] =
      "asdsfgfgdfgdfgdfgdfgfdggdssssssdddddddddddddwdfrgthyjghgfdfefsfefesfesf";
  char s2[] =
      "asdsfgfgdfgdfgdfgdfgfdggdssssssdddddddddddddwdfrgthyjghgfdfefsfefesfesd";
  unsigned char hash[htest->gethlen()], hashcmp[htest->gethlen()];
  htest->getStringHash((unsigned char *)s1, strlen(s1), hash);
  htest->getStringHash((unsigned char *)s2, strlen(s2), hashcmp);
  EXPECT_FALSE(cmpstr(hash, hashcmp, htest->gethlen()));
}
TEST(TNAME, TSNAME(5)) {
  FILE *fp1 = genfile("asdsfgfgdfgdfgdfgdfgfdggdssssssdddddddddddddwdfrgthyjghgfdfefsfefesfesf");
  FILE *fp2 = genfile("asdsfgfgdfgdfgdfgdfgfdggdssssssdddddddddddddwdfrgthyjghgfdfefsfefesfesd");
  unsigned char b1[256] = {0}, b2[256] = {0};
  size_t n1 = fread(b1, 1, sizeof(b1), fp1);
  size_t n2 = fread(b2, 1, sizeof(b2), fp2);
  unsigned char hash[htest->gethlen()], hashcmp[htest->gethlen()];
  htest->getStringHash(b1, (unsigned int)n1, hash);
  htest->getStringHash(b2, (unsigned int)n2, hashcmp);
  EXPECT_FALSE(cmpstr(hash, hashcmp, htest->gethlen()));
  fclose(fp1);
  fclose(fp2);
}

int main(int argc, char **argv) {
  HashFactory hf;
  htest = hf.getHasher(HashFactory::HASH_TYPE::SHA256);
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}