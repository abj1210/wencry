#include "aes.h"
#include "util.h"

extern struct state keyg[11];
extern struct buffer ibuf, obuf; //输入和输出缓冲区
/*
addroundkey:aes的密钥轮加操作
w:待操作的aes加解密单元指针
key:相应的轮密钥指针
*/
void addroundkey(struct state &w, const struct state &key) {
  w.g[0] ^= key.g[0];
  w.g[1] ^= key.g[1];
  w.g[2] ^= key.g[2];
  w.g[3] ^= key.g[3];
}
/*
subbytes:aes的subbytes操作
w:待操作的aes加解密单元指针
*/
void subbytes(struct state &w) {
  for (int i = 0; i < 4; ++i) {
    unsigned int t = w.g[i];
    w.g[i] = ((unsigned int)sub_bytes((unsigned char)t)) |
             ((unsigned int)sub_bytes((unsigned char)(t >> 8)) << 8) |
             ((unsigned int)sub_bytes((unsigned char)(t >> 16)) << 16) |
             ((unsigned int)sub_bytes((unsigned char)(t >> 24)) << 24);
  }
}
/*
rowshift:aes的rowshift操作
w:待操作的aes加解密单元指针
*/
void rowshift(struct state &w) {
  w.g[1] = rrot(w.g[1], 8);
  w.g[2] = rrot(w.g[2], 16);
  w.g[3] = rrot(w.g[3], 24);
}
/*
columnmix:aes的columnmix操作
w:待操作的aes加解密单元指针
*/
void columnmix(struct state &w) {
  unsigned int g0 = w.g[0], g1 = w.g[1], g2 = w.g[2], g3 = w.g[3];
  for (int i = 0; i < 4; ++i) {
    unsigned char b0 = g0, b1 = g1, b2 = g2, b3 = g3;
    w.s[0][i] = GMline(25, 1, 0, 0);
    w.s[1][i] = GMline(0, 25, 1, 0);
    w.s[2][i] = GMline(0, 0, 25, 1);
    w.s[3][i] = GMline(1, 0, 0, 25);

    g0 >>= 8, g1 >>= 8, g2 >>= 8, g3 >>= 8;
  }
}
/*
commonround:aes的一轮加密步骤
data:待操作的aes加解密单元指针
round:该操作的轮数
*/
void commonround(struct state &data, int round) {
  addroundkey(data, keyg[round]);
  subbytes(data);
  rowshift(data);
  columnmix(data);
}
/*
commonround:aes的最后一轮加密步骤
data:待操作的aes加解密单元指针
*/
void lastround(struct state &data) {
  addroundkey(data, keyg[9]);
  subbytes(data);
  rowshift(data);
  addroundkey(data, keyg[10]);
}
/*
接口函数
runaes_128bit:将一个128bit的数据块进行aes加密
s:待加解密数据块的地址
*/
void runaes_128bit(struct state &s) {
  for (int i = 0; i < 9; ++i)
    commonround(s, i);
  lastround(s);
}