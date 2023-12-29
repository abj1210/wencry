#include "sha1.h"
#include "testutil.h"
#include "gtest/gtest.h"

TEST(Testsha1, testsha1_1) {
  char s1[] = "abcd";
  unsigned char hash[20], hashcmp[20];
  sha1Stringhash stest((unsigned char *)s1, 4);
  stest.getres(hash);
  gethex("81fe8bfe87576c3ecb22426f8e57847382917acf", hashcmp);
  EXPECT_TRUE(cmpstr(hash, hashcmp, 20));
}

TEST(Testsha1, testsha1_2) {
  char s1[] =
      "asdsfgfgdfgdfgdfgdfgfdggdssssssdddddddddddddwdfrgthyjghgfdfefsfefesfesf";
  unsigned char hash[20], hashcmp[20];
  sha1Stringhash stest((unsigned char *)s1, strlen(s1));
  stest.getres(hash);
  gethex("fd15bb59b548b867c5abe2460d93be2f44a6b1cf", hashcmp);
  EXPECT_TRUE(cmpstr(hash, hashcmp, 20));
}

TEST(Testsha1, testsha1_3) {
  FILE *fp = genfile("abcd");
  unsigned char hash[20], hashcmp[20];
  sha1Filehash ftest(fp);
  ftest.getres(hash);
  gethex("81fe8bfe87576c3ecb22426f8e57847382917acf", hashcmp);
  EXPECT_TRUE(cmpstr(hash, hashcmp, 20));
  fclose(fp);
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}