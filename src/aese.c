#include "../include/aes.h"
#include "../include/util.h"

extern const unsigned char s_box[256], rs_box[256];
extern const unsigned char Logtable[256], Alogtable[512];
extern struct state keyg[11];
extern struct buffer ibuf, obuf; //输入和输出缓冲区
/*
addroundkey:aes的密钥轮加操作
w:待操作的aes加解密单元指针
key:相应的轮密钥指针
*/
void addroundkey(struct state *w, struct state *key) {
  for (int i = 0; i < 4; ++i)
    *(unsigned int *)w->s[i] ^= *((unsigned int *)key->s[i]);
}
/*
subbytes:aes的subbytes操作
w:待操作的aes加解密单元指针
*/
void subbytes(struct state *w) {
  for (int i = 0; i < 4; ++i) {
    unsigned int t = *((unsigned int *)w->s[i]);
    *((unsigned int *)w->s[i]) =
        ((unsigned int)sub_bytes(t & 0xff)) |
        ((unsigned int)sub_bytes((t >> 8) & 0xff) << 8) |
        ((unsigned int)sub_bytes((t >> 16) & 0xff) << 16) |
        ((unsigned int)sub_bytes((t >> 24) & 0xff) << 24);
  }
}
/*
rowshift:aes的rowshift操作
w:待操作的aes加解密单元指针
*/
void rowshift(struct state *w) {
  for (int i = 0; i < 4; ++i) {
    unsigned int *p = (unsigned int *)w->s[i];
    *p = rrot(*p, i << 3);
  }
}
/*
columnmix:aes的columnmix操作
w:待操作的aes加解密单元指针
*/
void columnmix(struct state *w) {

  for (unsigned char *p = ((unsigned char *)(w->s)), *pe = p + 0x4; p != pe;
       ++p) {
    unsigned char b0 = *p, b1 = *(p + 0x4), b2 = *(p + 0x8), b3 = *(p + 0xc);
    (*p) = GMline(0x02, 0x03, 0x01, 0x01);
    (*(p + 0x4)) = GMline(0x01, 0x02, 0x03, 0x01);
    (*(p + 0x8)) = GMline(0x01, 0x01, 0x02, 0x03);
    (*(p + 0xc)) = GMline(0x03, 0x01, 0x01, 0x02);
  }
}
/*
commonround:aes的一轮加密步骤
data:待操作的aes加解密单元指针
round:该操作的轮数
*/
void commonround(struct state *data, int round) {
  addroundkey(data, &keyg[round]);
  subbytes(data);
  rowshift(data);
  columnmix(data);
}
/*
commonround:aes的最后一轮加密步骤
data:待操作的aes加解密单元指针
*/
void lastround(struct state *data) {
  addroundkey(data, &keyg[9]);
  subbytes(data);
  rowshift(data);
  addroundkey(data, &keyg[10]);
}
/*
接口函数
runaes_128bit:将一个128bit的数据块进行aes加密
s:待加解密数据块的地址
*/
void runaes_128bit(unsigned char *s) {
  struct state *data = (struct state *)s;
  for (int i = 0; i < 9; ++i)
    commonround(data, i);
  lastround(data);
}