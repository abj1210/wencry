#include "cry.h"
#include "testutil.h"
#include "gtest/gtest.h"

TEST(Testhmac, testhmac_sha1) {
  FILE *fp = genfile("abcd"), *fp1 = genfile("abcdd");
  unsigned char key[16] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                           '0', '1', '2', '3', '4', '5', '6', '7'};
  hmac htest;
  unsigned char res[20], rescmp[20];
  memset(res, 0, sizeof(res));
  htest.gethmac(0, key, fp, res);
  gethex("549b8f83a4ae777e505b8698af6a2e577791948d", rescmp);
  EXPECT_TRUE(cmpstr(res, rescmp, 20));
  fclose(fp);
  fp = genfile("abcd");
  EXPECT_TRUE(htest.cmphmac(0, key, fp, res));
  EXPECT_FALSE(htest.cmphmac(0, key, fp1, res));
  fclose(fp);
  fp = genfile("abcd");
  key[0] = 'A';
  EXPECT_FALSE(htest.cmphmac(0, key, fp1, res));
  EXPECT_FALSE(htest.cmphmac(0, key, fp, res));
  fclose(fp);
  fclose(fp1);
}
TEST(Testhmac, testhmac_md5) {
  FILE *fp = genfile("abcd"), *fp1 = genfile("abcdd");
  unsigned char key[16] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                           '0', '1', '2', '3', '4', '5', '6', '7'};
  hmac htest;
  unsigned char res[16], rescmp[16];
  memset(res, 0, sizeof(res));
  htest.gethmac(1, key, fp, res);
  gethex("d8079d373ac038fc4155444251eaa8ce", rescmp);
  EXPECT_TRUE(cmpstr(res, rescmp, 16));
  fclose(fp);
  fp = genfile("abcd");
  EXPECT_TRUE(htest.cmphmac(1, key, fp, res));
  EXPECT_FALSE(htest.cmphmac(1, key, fp1, res));
  fclose(fp);
  fp = genfile("abcd");
  key[0] = 'A';
  EXPECT_FALSE(htest.cmphmac(1, key, fp1, res));
  EXPECT_FALSE(htest.cmphmac(1, key, fp, res));
  fclose(fp);
  fclose(fp1);
}
TEST(Testhmac, testhmac_sha256) {
  FILE *fp = genfile("abcd"), *fp1 = genfile("abcdd");
  unsigned char key[16] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                           '0', '1', '2', '3', '4', '5', '6', '7'};
  hmac htest;
  unsigned char res[32], rescmp[32];
  memset(res, 0, sizeof(res));
  htest.gethmac(2, key, fp, res);
  gethex("f676c53d0f72bc8a0b2fa63b57a68df8537414f9f66032c14b483376ed480d2d", rescmp);
  EXPECT_TRUE(cmpstr(res, rescmp, 32));
  fclose(fp);
  fp = genfile("abcd");
  EXPECT_TRUE(htest.cmphmac(2, key, fp, res));
  EXPECT_FALSE(htest.cmphmac(2, key, fp1, res));
  fclose(fp);
  fp = genfile("abcd");
  key[0] = 'A';
  EXPECT_FALSE(htest.cmphmac(2, key, fp1, res));
  EXPECT_FALSE(htest.cmphmac(2, key, fp, res));
  fclose(fp);
  fclose(fp1);
}
int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}