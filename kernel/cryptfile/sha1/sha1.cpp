#include "sha1.h"
#include <string.h>
/*
getwdata:根据每个输入单元生成sha1中w数组的值
*/
void sha1hash::getwdata() {
  u32_t t, i = 0;
  for (i; i < 16; ++i) {
    t = this->i[i];
    setbytes(w[i], ((u8_t)(t >> 24)), ((u8_t)(t >> 16)), ((u8_t)(t >> 8)), t);
  }
  for (i; i < 80; ++i) {
    t = (w[i - 3]) ^ (w[i - 8]) ^ (w[i - 14]) ^ (w[i - 16]);
    w[i] = lrot(t, 1);
  }
}
/*
gethash:获取每一步的哈希值
*/
void sha1hash::gethash() {
  getwdata();
  u32_t temph[5];
  memcpy(temph, h, sizeof(h));
  u32_t f, temp;
  for (u32_t i = 0; i < 80; ++i) {
    if (i < 20)
      f = ((temph[1] & temph[2]) | ((~temph[1]) & temph[3])) + 0x5A827999;
    else if (i < 40)
      f = (temph[1] ^ temph[2] ^ temph[3]) + 0x6ED9EBA1;
    else if (i < 60)
      f = ((temph[1] & temph[2]) | (temph[1] & temph[3]) |
           (temph[2] & temph[3])) +
          0x8F1BBCDC;
    else
      f = (temph[1] ^ temph[2] ^ temph[3]) + 0xCA62C1D6;
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
getLoadAddr:获取加载地址
reutrn:加载地址
*/
u8_t *sha1hash::getLoadAddr() {
  memset(s, 0, sizeof(s));
  return s;
}
/*
finalHash:结尾的哈希处理
loadsize:装载字节数
*/
void sha1hash::finalHash(u32_t loadsize) {
  s[loadsize] = 0x80u;
  if (loadsize >= 56) {
    gethash();
    memset(s, 0, sizeof(s));
  }

  for (int i = 0; i < 8; ++i) {
    s[56 + i] = (u8_t)(((u64_t)totalsize >> ((7 - i) << 3)));
  }
  gethash();
}
/*
接口函数
getres:获取哈希结果
hashout:输出字符串地址
*/
void sha1hash::getres(u8_t *hashout) {
  for (int i = 0; i < 20; ++i)
    hashout[i] = (u8_t)((h[i >> 2]) >> ((3 - (i & 0x3)) << 3));
}