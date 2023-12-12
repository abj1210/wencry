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
  u32_t nxt = turn ? 0 : 1;
  memcpy(h[nxt], h[turn], 20);
  u32_t f, temp;
  for (u32_t i = 0; i < 80; ++i) {
    if (i < 20)
      f = ((h[nxt][1] & h[nxt][2]) | ((~h[nxt][1]) & h[nxt][3])) + 0x5A827999;
    else if (i < 40)
      f = (h[nxt][1] ^ h[nxt][2] ^ h[nxt][3]) + 0x6ED9EBA1;
    else if (i < 60)
      f = ((h[nxt][1] & h[nxt][2]) | (h[nxt][1] & h[nxt][3]) |
          (h[nxt][2] & h[nxt][3])) + 0x8F1BBCDC;
    else 
      f = (h[nxt][1] ^ h[nxt][2] ^ h[nxt][3]) + 0xCA62C1D6;
    temp = lrot(h[nxt][0], 5) + f + h[nxt][4] + w[i];
    h[nxt][4] = h[nxt][3];
    h[nxt][3] = h[nxt][2];
    h[nxt][2] = lrot(h[nxt][1], 30);
    h[nxt][1] = h[nxt][0];
    h[nxt][0] = temp;
  }
  turn = nxt;
}
/*
getLoadAddr:获取加载地址
reutrn:加载地址
*/
u8_t * sha1hash::getLoadAddr(){
  memset(s,0,sizeof(s));
  return s;
}
/*
finalHash:结尾的哈希处理
loadsize:装载字节数
*/
void sha1hash::finalHash(u32_t loadsize){
  s[loadsize] = 0x80u;
  if (loadsize >= 56) {
    gethash();
    memset(s, 0, sizeof(s));
  }
  for (int i = 0; i < 8; ++i)
    s[56 + i] = (u8_t)((totalsize >> ((7 - i) << 3)));
  gethash();
}
/*
接口函数
getres:获取哈希结果
hashout:输出字符串地址
*/
void sha1hash::getres(u8_t *hashout) {
  for (int i = 0; i < 20; ++i)
    hashout[i] = (u8_t)((h[turn][i >> 2]) >> ((3 - (i & 0x3)) << 3));
}
/*
接口函数
cmphash:比较哈希值
hash:带比较的哈希值
return:比较是否相等
*/
bool sha1hash::cmphash(u8_t *hash) const {
  for (int i = 0; i < 20; ++i) {
    if ((u8_t)((h[turn][i >> 2]) >> ((3 - (i & 0x3)) << 3)) != hash[i])
      return false;
  }
  return true;
}