#include "hashmaster.h"
#include <string.h>
#define HASH_A(h1, h2, h3) ((h1 & h2) | ((~h1) & h3))

#define HASH_B(h1, h2, h3) (h1 ^ h2 ^ h3)

#define HASH_C(h1, h2, h3) ((h1 & h2) | (h1 & h3) | (h2 & h3))
/*
getwdata:根据每个输入单元生成sha1中w数组的值
*/
void sha1hash::getwdata()
{
  u32_t t, i = 0;
  for (i; i < 16; ++i)
  {
    t = this->i[i];
    setbytes(w[i], ((u8_t)(t >> 24)), ((u8_t)(t >> 16)), ((u8_t)(t >> 8)), t);
  }
  for (i; i < 80; ++i)
  {
    t = (w[i - 3]) ^ (w[i - 8]) ^ (w[i - 14]) ^ (w[i - 16]);
    w[i] = lrot(t, 1);
  }
}
/*
gethash:获取每一步的哈希值
*/
void sha1hash::getHash(const u8_t *input)
{
  memset(s, 0, sizeof(s));
  memcpy(s, input, sizeof(s));
  getwdata();
  addtotal(64);
  u32_t temph[5];
  memcpy(temph, h, sizeof(h));
  u32_t f, temp;
  for (u32_t i = 0; i < 80; ++i)
  {
    if (i < 20)
      f = HASH_A(temph[1], temph[2], temph[3]) + 0x5A827999;
    else if (i < 40)
      f = HASH_B(temph[1], temph[2], temph[3]) + 0x6ED9EBA1;
    else if (i < 60)
      f = HASH_C(temph[1], temph[2], temph[3]) + 0x8F1BBCDC;
    else
      f = HASH_B(temph[1], temph[2], temph[3]) + 0xCA62C1D6;
    temp = lrot(temph[0], 5) + f + temph[4] + w[i];
    temph[4] = temph[3];
    temph[3] = temph[2];
    temph[2] = lrot(temph[1], 30);
    temph[1] = temph[0];
    temph[0] = temp;
  }
  for (u32_t i = 0; i < 5; ++i)
    h[i] += temph[i];
}

/*
finalHash:结尾的哈希处理
loadsize:装载字节数
*/
void sha1hash::getHash(const u8_t *input, u32_t final_loadsize)
{
  addtotal(final_loadsize);
  u8_t *temp = new u8_t[getblen()];
  memset(temp, 0, getblen());
  memcpy(temp, input, final_loadsize);
  temp[final_loadsize] = 0x80u;
  if (final_loadsize >= 56)
  {
    getHash(temp);
    memset(temp, 0, getblen());
  }
  for (int i = 0; i < 8; ++i)
  {
    temp[56 + i] = (u8_t)(((u64_t)totalsize >> ((7 - i) << 3)));
  }
  getHash(temp);
  delete[] temp;
}
/*
接口函数
getres:获取哈希结果
hashout:输出字符串地址
*/
void sha1hash::getres(u8_t *hashout)
{
  for (int i = 0; i < 20; ++i)
    hashout[i] = (u8_t)((h[i >> 2]) >> ((3 - (i & 0x3)) << 3));
}