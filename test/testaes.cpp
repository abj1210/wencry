#include "aes_ni.h"
#include "testutil.h"
#include "gtest/gtest.h"

TEST(Testaes, testres) {
  unsigned char key[16] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                           '0', '1', '2', '3', '4', '5', '6', '7'};
  EncryAes etest(key);
  unsigned char block[] = "I'm a test msg.";
  unsigned char aescmp[16];
  __m128i s = _mm_loadu_si128((const __m128i *)block);
  s = etest.runaes_128bit(s);
  _mm_storeu_si128((__m128i*)block, s);
  gethex("e3481e03f1a1a6ccdf72a155cd88732b", aescmp);
  EXPECT_TRUE(cmpstr(block, aescmp, 16));
}
TEST(Testaes, testround1) {
  unsigned char key[16] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                           '0', '1', '2', '3', '4', '5', '6', '7'};
  EncryAes etest(key);
  DecryAes dtest(key);
  unsigned char block[] = "I'm a test msg.";
  unsigned char aescmp[] = "I'm a test msg.";
  __m128i s = _mm_loadu_si128((const __m128i *)block);
  s = etest.runaes_128bit(s);
  _mm_storeu_si128((__m128i*)block, s);
  s = _mm_loadu_si128((const __m128i *)block);
  s = dtest.runaes_128bit(s);
  _mm_storeu_si128((__m128i*)block, s);
  EXPECT_TRUE(cmpstr(block, aescmp, 16));
}
TEST(Testaes, testround2) {
  unsigned char key[16] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                           '0', '1', '2', '3', '4', '5', '6', '7'};
  EncryAes etest(key);
  key[0] = 'A';
  DecryAes dtest(key);
  unsigned char block[] = "I'm a test msg.";
  unsigned char aescmp[] = "I'm a test msg.";
  __m128i s = _mm_loadu_si128((const __m128i *)block);
  s = etest.runaes_128bit(s);
  _mm_storeu_si128((__m128i*)block, s);
  s = _mm_loadu_si128((const __m128i *)block);
  s = dtest.runaes_128bit(s);
  _mm_storeu_si128((__m128i*)block, s);
  EXPECT_FALSE(cmpstr(block, aescmp, 16));
}
int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}