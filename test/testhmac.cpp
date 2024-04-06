#include "cry.h"
#include "testutil.h"
#include "gtest/gtest.h"

TEST(Testhmac, testhmac_sha1) {
  FILE *fp = genfile("abcd"), *fp1 = genfile("abcdd");
  unsigned char key[16] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                           '0', '1', '2', '3', '4', '5', '6', '7'};
  hmac htest(0);
  unsigned char res[20], rescmp[20];
  memset(res, 0, sizeof(res));
  htest.gethmac(key, fp, res);
  gethex("549b8f83a4ae777e505b8698af6a2e577791948d", rescmp);
  EXPECT_TRUE(cmpstr(res, rescmp, 20));
  fclose(fp);
  fp = genfile("abcd");
  EXPECT_TRUE(htest.cmphmac(key, fp, res));
  EXPECT_FALSE(htest.cmphmac(key, fp1, res));
  fclose(fp);
  fp = genfile("abcd");
  key[0] = 'A';
  EXPECT_FALSE(htest.cmphmac(key, fp1, res));
  EXPECT_FALSE(htest.cmphmac(key, fp, res));
  fclose(fp);
  fclose(fp1);
}
TEST(Testhmac, testhmac_md5) {
  FILE *fp = genfile("abcd"), *fp1 = genfile("abcdd");
  unsigned char key[16] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                           '0', '1', '2', '3', '4', '5', '6', '7'};
  hmac htest(1);
  unsigned char res[16], rescmp[16];
  memset(res, 0, sizeof(res));
  htest.gethmac(key, fp, res);
  gethex("d8079d373ac038fc4155444251eaa8ce", rescmp);
  EXPECT_TRUE(cmpstr(res, rescmp, 16));
  fclose(fp);
  fp = genfile("abcd");
  EXPECT_TRUE(htest.cmphmac(key, fp, res));
  EXPECT_FALSE(htest.cmphmac(key, fp1, res));
  fclose(fp);
  fp = genfile("abcd");
  key[0] = 'A';
  EXPECT_FALSE(htest.cmphmac(key, fp1, res));
  EXPECT_FALSE(htest.cmphmac(key, fp, res));
  fclose(fp);
  fclose(fp1);
}
int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}