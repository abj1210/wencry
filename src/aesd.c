#include "aes.h"
#include "util.h"

extern const unsigned char s_box[256], rs_box[256];
extern const unsigned char Logtable[256], Alogtable[512];
extern struct state keyg[11];
extern struct buffer ibuf, obuf; //输入和输出缓冲区
extern void addroundkey(struct state *w, struct state *key);
/*
resubbytes:aes的还原subbytes步骤
w:待操作的aes加解密单元指针
*/
void resubbytes(struct state *w) {
  for (int i = 0; i < 4; ++i) {
    unsigned int t = *((unsigned int *)w->s[i]);
    *((unsigned int *)w->s[i]) =
        ((unsigned int)r_sub_bytes((unsigned char)t)) |
        ((unsigned int)r_sub_bytes((unsigned char)(t >> 8)) << 8) |
        ((unsigned int)r_sub_bytes((unsigned char)(t >> 16)) << 16) |
        ((unsigned int)r_sub_bytes((unsigned char)(t >> 24)) << 24);
  }
}
/*
rerowshift:aes的还原rowshift步骤
w:待操作的aes加解密单元指针
*/
void rerowshift(struct state *w) {
  *(unsigned int *)w->s[1] = lrot(*(unsigned int *)w->s[1], 8);
  *(unsigned int *)w->s[2] = lrot(*(unsigned int *)w->s[2], 16);
  *(unsigned int *)w->s[3] = lrot(*(unsigned int *)w->s[3], 24);
}
/*
recolumnmix:aes的还原columnmix步骤
w:待操作的aes加解密单元指针
*/
static void recolumnmix(struct state *w) {
  for (register unsigned char *p = ((unsigned char *)(w->s)), *pe = p + 0x4;
       p != pe; ++p) {
    register unsigned char b0 = *p, b1 = *(p + 0x4), b2 = *(p + 0x8),
                           b3 = *(p + 0xc);
    (*p) = GMline(223, 104, 238, 199);
    (*(p + 0x4)) = GMline(199, 223, 104, 238);
    (*(p + 0x8)) = GMline(238, 199, 223, 104);
    (*(p + 0xc)) = GMline(104, 238, 199, 223);
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
  firstdec((struct state *)s);
  for (int i = 8; i >= 0; --i)
    commondec((struct state *)s, i);
}