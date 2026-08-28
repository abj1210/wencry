#include "merkletree.h"
#include "testutil.h"
#include "gtest/gtest.h"

#include <cstring>

/* 测试密钥(16 字节) */
static const unsigned char key[16] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                                      '0', '1', '2', '3', '4', '5', '6', '7'};

/*
compute_hmac:对字符串数据计算一次性HMAC并输出到 out
htype:哈希类型(0=sha1,1=md5,2=sha256)
key:密钥
data:待计算数据(按 strlen 字节)
out:输出摘要缓冲(长度应不小于对应摘要长度)
*/
static void compute_hmac(u8_t htype, const unsigned char *key, const char *data,
                         unsigned char *out)
{
  hmac h;
  h.gethmac(htype, (u8_t *)key, (const u8_t *)data, out, strlen(data), NULL, 0);
}

/*
verify_case:针对一种哈希类型做参考向量与差异性校验
htype:哈希类型
expected_hex:参考摘要(十六进制字符串)
hlen:摘要字节长度
*/
static void verify_case(u8_t htype, const char *expected_hex, size_t hlen)
{
  unsigned char res[32], cmp[32], other[32];
  memset(res, 0, sizeof(res));

  compute_hmac(htype, key, "abcd", res);
  gethex(expected_hex, cmp);
  EXPECT_EQ(std::memcmp(res, cmp, hlen), 0);

  // 数据不同 => HMAC 应不同
  compute_hmac(htype, key, "abcdd", other);
  EXPECT_NE(std::memcmp(res, other, hlen), 0);

  // 密钥不同 => HMAC 应不同
  unsigned char badkey[16];
  memcpy(badkey, key, sizeof(badkey));
  badkey[0] = 'A';
  compute_hmac(htype, badkey, "abcd", other);
  EXPECT_NE(std::memcmp(res, other, hlen), 0);
}

TEST(Testhmac, testhmac_sha1) {
  verify_case(HT_SHA1, "549b8f83a4ae777e505b8698af6a2e577791948d", 20);
}

TEST(Testhmac, testhmac_md5) {
  verify_case(HT_MD5, "d8079d373ac038fc4155444251eaa8ce", 16);
}

TEST(Testhmac, testhmac_sha256) {
  verify_case(HT_SHA256,
              "f676c53d0f72bc8a0b2fa63b57a68df8537414f9f66032c14b483376ed480d2d",
              32);
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
