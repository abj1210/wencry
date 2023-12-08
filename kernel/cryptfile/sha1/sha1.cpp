#include "sha1.h"
#include "macro.h"
/*
getwdata:根据每个输入单元生成sha1中w数组的值
s:输入的单元
*/
void sha1hash::getwdata(const u8_t *s) {
  u32_t t, i = 0;
  for (i; i < 16; ++i) {
    t = *((u32_t *)s + i);
    setbytes(w.w[i], ((u8_t)(t >> 24)), ((u8_t)(t >> 16)), ((u8_t)(t >> 8)), t);
  }
  for (i; i < 80; ++i) {
    t = (w.w[i - 3]) ^ (w.w[i - 8]) ^ (w.w[i - 14]) ^ (w.w[i - 16]);
    w.w[i] = lrot(t, 1);
  }
}
/*
gethash:获取每一步的哈希值
h:上一步的哈希值
w:生成的w数组
*/
void sha1hash::gethash() {
  u32_t temph0 = h[0], temph1 = h[1], temph2 = h[2], temph3 = h[3],
        temph4 = h[4];
  u32_t f, temp;
  for (u32_t i = 0; i < 80; ++i) {
    if (i < 20) {
      f = (temph1 & temph2) | ((~temph1) & temph3);
      temp = lrot(temph0, 5) + f + 0x5A827999 + temph4 + w.w[i];
    } else if (i < 40) {
      f = temph1 ^ temph2 ^ temph3;
      temp = lrot(temph0, 5) + f + 0x6ED9EBA1 + temph4 + w.w[i];
    } else if (i < 60) {
      f = (temph1 & temph2) | (temph1 & temph3) | (temph2 & temph3);
      temp = lrot(temph0, 5) + f + 0x8F1BBCDC + temph4 + w.w[i];
    } else {
      f = temph1 ^ temph2 ^ temph3;
      temp = lrot(temph0, 5) + f + 0xCA62C1D6 + temph4 + w.w[i];
    }
    temph4 = temph3;
    temph3 = temph2;
    temph2 = lrot(temph1, 30);
    temph1 = temph0;
    temph0 = temp;
  }
  h[0] += temph0, h[1] += temph1, h[2] += temph2, h[3] += temph3, h[4] += temph4;
}
/*
接口函数
getres:获取哈希结果
hashout:输出字符串地址
*/
void sha1hash::getres(u8_t * hashout){
  for (int i = 0; i < 20; ++i)
    hashout[i] = (u8_t)((h[i >> 2]) >> ((3 - (i & 0x3)) << 3));
}
/*
接口函数
cmphash:比较哈希值
hash:带比较的哈希值
return:比较是否相等
*/
bool sha1hash::cmphash(u8_t * hash){
  for (int i = 0; i < 20; ++i)
    if((u8_t)((h[i >> 2]) >> ((3 - (i & 0x3)) << 3))!=hash[i])return false;
  return true;
}