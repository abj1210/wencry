#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/aes.h"
#include "../include/util.h"
/*
resubbytes:aes的还原subbytes步骤
w:待操作的aes加解密单元指针
*/
void resubbytes(struct state *w) {
  for (int i = 0; i < 4; ++i) {
    unsigned char t0 = w->s[i][0], t1 = w->s[i][1], t2 = w->s[i][2],
                  t3 = w->s[i][3];
    *((unsigned int *)w->s[i]) = ((unsigned int)r_sub_bytes(t0)) |
                                 ((unsigned int)r_sub_bytes(t1) << 8) |
                                 ((unsigned int)r_sub_bytes(t2) << 16) |
                                 ((unsigned int)r_sub_bytes(t3) << 24);
  }
}
/*
rerowshift:aes的还原rowshift步骤
w:待操作的aes加解密单元指针
*/
void rerowshift(struct state *w) {
  for (int i = 0; i < 4; ++i) {
    unsigned int *p = (unsigned int *)w->s[i];
    *p = lrot(*p, i << 3);
  }
}
/*
recolumnmix:aes的还原columnmix步骤
w:待操作的aes加解密单元指针
*/
void recolumnmix(struct state *w) {
  unsigned char *p = ((unsigned char *)(w->s)), *pe = p + 0x4;
  while (p != pe) {
    unsigned char b0 = *p, b1 = *(p + 0x4), b2 = *(p + 0x8), b3 = *(p + 0xc);
    unsigned short GIline(0x0e, 0x0b, 0x0d, 0x09);
    (*p) = GMline;

    GIline(0x09, 0x0e, 0x0b, 0x0d);
    (*(p + 0x4)) = GMline;

    GIline(0x0d, 0x09, 0x0e, 0x0b);
    (*(p + 0x8)) = GMline;

    GIline(0x0b, 0x0d, 0x09, 0x0e);
    (*(p + 0xc)) = GMline;

    p++;
  }
}
/*
commondec:aes的一轮解密步骤
data:待操作的aes加解密单元指针
round:该操作的轮数
*/
void commondec(struct state *data, int round) {
  recolumnmix(data);
  rerowshift(data);
  resubbytes(data);
  addroundkey(data, &keyg[round]);
}
/*
firstdec:aes的第一轮解密步骤
data:待操作的aes加解密单元指针
*/
void firstdec(struct state *data) {
  addroundkey(data, &keyg[10]);
  rerowshift(data);
  resubbytes(data);
  addroundkey(data, &keyg[9]);
}
/*
decaes_128bit:将一个128bit的数据块进行aes解密
s:待加解密数据块的地址
*/
void decaes_128bit(unsigned char *s) {
  struct state *data = (struct state *)s;
  firstdec(data);
  for (int i = 8; i >= 0; --i)
    commondec(data, i);
}