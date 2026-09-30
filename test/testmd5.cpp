#include "hashmaster/hashmaster.h"
#include "merkletree.h"
#include "testutil.h"
#include "gtest/gtest.h"

/* 摘要缓冲区上界:SHA-256 为 32 字节,取 64 留余量。
   不能写成 hash[htest->getHashLength()]:变长数组不是标准 C++,MSVC 会报 C2131。 */
static const int HASH_DIGEST_MAX = 64;

#define TNAME Testmd5
#define TSNAME(tname) TNAME_##tname

HashMaster *htest;

TEST(TNAME, TSNAME(1)) {
  char s1[] = "abcd";
  unsigned char hash[HASH_DIGEST_MAX], hashcmp[HASH_DIGEST_MAX];
  htest->getStringHash((unsigned char *)s1, 4, hash);
  gethex("E2FC714C4727EE9395F324CD2E7F331F", hashcmp);
  EXPECT_TRUE(cmpstr(hash, hashcmp, htest->getHashLength()));
}

TEST(TNAME, TSNAME(2)) {
  char s1[] =
      "asdsfgfgdfgdfgdfgdfgfdggdssssssdddddddddddddwdfrgthyjghgfdfefsfefesfesf";
  unsigned char hash[HASH_DIGEST_MAX], hashcmp[HASH_DIGEST_MAX];
  htest->getStringHash((unsigned char *)s1, strlen(s1), hash);
  gethex("A3633338CD8C1462E58B03EF3158C48F", hashcmp);
  EXPECT_TRUE(cmpstr(hash, hashcmp, htest->getHashLength()));
}

TEST(TNAME, TSNAME(3)) {
  FILE *fp = genfile("abcd");
  unsigned char buf[64] = {0};
  size_t n = fread(buf, 1, sizeof(buf), fp);
  unsigned char hash[HASH_DIGEST_MAX], hashcmp[HASH_DIGEST_MAX];
  htest->getStringHash(buf, (unsigned int)n, hash);
  gethex("E2FC714C4727EE9395F324CD2E7F331F", hashcmp);
  EXPECT_TRUE(cmpstr(hash, hashcmp, htest->getHashLength()));
  fclose(fp);
}
TEST(TNAME, TSNAME(4)) {
  char s1[] =
      "asdsfgfgdfgdfgdfgdfgfdggdssssssdddddddddddddwdfrgthyjghgfdfefsfefesfesf";
  char s2[] =
      "asdsfgfgdfgdfgdfgdfgfdggdssssssdddddddddddddwdfrgthyjghgfdfefsfefesfesd";
  unsigned char hash[HASH_DIGEST_MAX], hashcmp[HASH_DIGEST_MAX];
  htest->getStringHash((unsigned char *)s1, strlen(s1), hash);
  htest->getStringHash((unsigned char *)s2, strlen(s2), hashcmp);
  EXPECT_FALSE(cmpstr(hash, hashcmp, htest->getHashLength()));
}
TEST(TNAME, TSNAME(5)) {
  FILE *fp1 = genfile("asdsfgfgdfgdfgdfgdfgfdggdssssssdddddddddddddwdfrgthyjghgfdfefsfefesfesf");
  FILE *fp2 = genfile("asdsfgfgdfgdfgdfgdfgfdggdssssssdddddddddddddwdfrgthyjghgfdfefsfefesfesd");
  unsigned char b1[256] = {0}, b2[256] = {0};
  size_t n1 = fread(b1, 1, sizeof(b1), fp1);
  size_t n2 = fread(b2, 1, sizeof(b2), fp2);
  unsigned char hash[HASH_DIGEST_MAX], hashcmp[HASH_DIGEST_MAX];
  htest->getStringHash(b1, (unsigned int)n1, hash);
  htest->getStringHash(b2, (unsigned int)n2, hashcmp);
  EXPECT_FALSE(cmpstr(hash, hashcmp, htest->getHashLength()));
  fclose(fp1);
  fclose(fp2);
}

int main(int argc, char **argv) {
  HashFactory hf;
  htest = hf.getHasher(HT_MD5);
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}