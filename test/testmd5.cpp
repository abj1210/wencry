#include "hashmaster.h"
#include "hashbuffer.h"
#include "testutil.h"
#include "gtest/gtest.h"

#define TNAME Testmd5
#define TSNAME(tname) TNAME_##tname

Hashmaster *htest;

TEST(TNAME, TSNAME(1)) {
  char s1[] = "abcd";
  unsigned char hash[htest->gethlen()], hashcmp[htest->gethlen()];
  htest->getStringHash((unsigned char *)s1, 4, hash);
  gethex("E2FC714C4727EE9395F324CD2E7F331F", hashcmp);
  EXPECT_TRUE(cmpstr(hash, hashcmp, htest->gethlen()));
}

TEST(TNAME, TSNAME(2)) {
  char s1[] =
      "asdsfgfgdfgdfgdfgdfgfdggdssssssdddddddddddddwdfrgthyjghgfdfefsfefesfesf";
  unsigned char hash[htest->gethlen()], hashcmp[htest->gethlen()];
  htest->getStringHash((unsigned char *)s1, strlen(s1), hash);
  gethex("A3633338CD8C1462E58B03EF3158C48F", hashcmp);
  EXPECT_TRUE(cmpstr(hash, hashcmp, htest->gethlen()));
}

TEST(TNAME, TSNAME(3)) {
  FILE *fp = genfile("abcd");
  unsigned char hash[htest->gethlen()], hashcmp[htest->gethlen()];
  buffer64 * buf = new filebuffer64(fp); 
  htest->getFileHash(buf, hash);
  gethex("E2FC714C4727EE9395F324CD2E7F331F", hashcmp);
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
  unsigned char hash[htest->gethlen()], hashcmp[htest->gethlen()];
  buffer64 * buf1 = new filebuffer64(fp1); 
  htest->getFileHash(buf1, hash);
  buffer64 * buf2 = new filebuffer64(fp2);
  htest->getFileHash(buf2, hashcmp);
  EXPECT_FALSE(cmpstr(hash, hashcmp, htest->gethlen()));
  delete buf1;
  delete buf2;
  fclose(fp1);
  fclose(fp2);
}

int main(int argc, char **argv) {
  HashFactory hf;
  htest = hf.getHasher(HashFactory::HASH_TYPE::MD5);
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}