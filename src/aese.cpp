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
  unsigned int *p = (unsigned int *)w.s[0], *k = (unsigned int *)key.s[0];
  *p ^= *k, *(p + 1) ^= *(k + 1), *(p + 2) ^= *(k + 2), *(p + 3) ^= *(k + 3);
}
/*
subbytes:aes的subbytes操作
w:待操作的aes加解密单元指针
*/
void subbytes(struct state &w) {
  unsigned int *p = (unsigned int *)w.s[0];
  for (int i = 0; i < 4; ++i) {
    unsigned int t = *(p + i);
    *(p + i) = ((unsigned int)sub_bytes((unsigned char)t)) |
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
  unsigned int *p = (unsigned int *)w.s[1];
  *p = rrot(*p, 8);
  *(p + 1) = rrot(*(p + 1), 16);
  *(p + 2) = rrot(*(p + 2), 24);
}
/*
columnmix:aes的columnmix操作
w:待操作的aes加解密单元指针
*/
void columnmix(struct state &w) {
  for (unsigned char *p = ((unsigned char *)(w.s)), *pe = p + 0x4;
       p != pe; ++p) {
    unsigned char b0 = *p, b1 = *(p + 0x4), b2 = *(p + 0x8),
                           b3 = *(p + 0xc);
    (*p) = GMline(25, 1, 0, 0);
    (*(p + 0x4)) = GMline(0, 25, 1, 0);
    (*(p + 0x8)) = GMline(0, 0, 25, 1);
    (*(p + 0xc)) = GMline(1, 0, 0, 25);
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
void runaes_128bit(unsigned char *s) {
  for (int i = 0; i < 9; ++i)
    commonround(*(struct state *)s, i);
  lastround(*(struct state *)s);
}