#include "../include/aes.h"
#include "../include/util.h"

extern void addroundkey(struct state *w, struct state *key);
extern const unsigned char s_box[256], rs_box[256];
extern const unsigned char Logtable[256], Alogtable[512];
extern struct state keyg[11];
extern struct buffer ibuf, obuf; //输入和输出缓冲区
/*
resubbytes:aes的还原subbytes步骤
w:待操作的aes加解密单元指针
*/
void resubbytes(struct state *w) {
  for (int i = 0; i < 4; ++i) {
    unsigned int t = *((unsigned int *)w->s[i]);
    *((unsigned int *)w->s[i]) =
        ((unsigned int)r_sub_bytes(t & 0xff)) |
        ((unsigned int)r_sub_bytes((t >> 8) & 0xff) << 8) |
        ((unsigned int)r_sub_bytes((t >> 16) & 0xff) << 16) |
        ((unsigned int)r_sub_bytes((t >> 24) & 0xff) << 24);
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
  for (unsigned char *p = ((unsigned char *)(w->s)), *pe = p + 0x4; p != pe;
       ++p) {
    unsigned char b0 = *p, b1 = *(p + 0x4), b2 = *(p + 0x8), b3 = *(p + 0xc);
    (*p) = GMline(0x0e, 0x0b, 0x0d, 0x09);
    (*(p + 0x4)) = GMline(0x09, 0x0e, 0x0b, 0x0d);
    (*(p + 0x8)) = GMline(0x0d, 0x09, 0x0e, 0x0b);
    (*(p + 0xc)) = GMline(0x0b, 0x0d, 0x09, 0x0e);
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
接口函数
decaes_128bit:将一个128bit的数据块进行aes解密
s:待加解密数据块的地址
*/
void decaes_128bit(unsigned char *s) {
  struct state *data = (struct state *)s;
  firstdec(data);
  for (int i = 8; i >= 0; --i)
    commondec(data, i);
}