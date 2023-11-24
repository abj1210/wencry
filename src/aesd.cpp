#include "aes.h"
#include "util.h"

extern struct state keyg[11];
extern struct buffer ibuf, obuf; //输入和输出缓冲区
/*
addroundkey:aes的密钥轮加操作
w:待操作的aes加解密单元指针
key:相应的轮密钥指针
*/
extern void addroundkey(struct state &w, const struct state &key);
/*
resubbytes:aes的还原subbytes步骤
w:待操作的aes加解密单元指针
*/
void resubbytes(struct state &w) {
  for (int i = 0; i < 4; ++i) {
    unsigned int t = w.g[i];
    w.g[i] = ((unsigned int)r_sub_bytes((unsigned char)t)) |
             ((unsigned int)r_sub_bytes((unsigned char)(t >> 8)) << 8) |
             ((unsigned int)r_sub_bytes((unsigned char)(t >> 16)) << 16) |
             ((unsigned int)r_sub_bytes((unsigned char)(t >> 24)) << 24);
  }
}
/*
rerowshift:aes的还原rowshift步骤
w:待操作的aes加解密单元指针
*/
void rerowshift(struct state &w) {
  w.g[1] = lrot(w.g[1], 8);
  w.g[2] = lrot(w.g[2], 16);
  w.g[3] = lrot(w.g[3], 24);
}
/*
recolumnmix:aes的还原columnmix步骤
w:待操作的aes加解密单元指针
*/
void recolumnmix(struct state &w) {
  unsigned int g0 = w.g[0], g1 = w.g[1], g2 = w.g[2], g3 = w.g[3];
  for (int i = 0; i < 4; ++i) {
    unsigned char b0 = g0, b1 = g1, b2 = g2, b3 = g3;
    w.s[0][i] = GMline(223, 104, 238, 199);
    w.s[1][i] = GMline(199, 223, 104, 238);
    w.s[2][i] = GMline(238, 199, 223, 104);
    w.s[3][i] = GMline(104, 238, 199, 223);

    g0 >>= 8, g1 >>= 8, g2 >>= 8, g3 >>= 8;
  }
}
/*
commondec:aes的一轮解密步骤
data:待操作的aes加解密单元指针
round:该操作的轮数
*/
void commondec(struct state &data, int round) {
  recolumnmix(data);
  rerowshift(data);
  resubbytes(data);
  addroundkey(data, keyg[round]);
}
/*
firstdec:aes的第一轮解密步骤
data:待操作的aes加解密单元指针
*/
void firstdec(struct state &data) {
  addroundkey(data, keyg[10]);
  rerowshift(data);
  resubbytes(data);
  addroundkey(data, keyg[9]);
}
/*
接口函数
decaes_128bit:将一个128bit的数据块进行aes解密
s:待加解密数据块的地址
*/
void decaes_128bit(struct state &s) {
  firstdec(s);
  for (int i = 8; i >= 0; --i)
    commondec(s, i);
}