#include "aes.h"
#include "util.h"

extern struct state keyg[11];
/*
addroundkey:aes的密钥轮加操作
w:待操作的aes加解密单元指针
key:相应的轮密钥指针
*/
void addroundkey(struct state &w, const struct state &key) {
  w.datal ^= key.datal;
  w.datah ^= key.datah;
}
/*
subbytes:aes的subbytes操作
w:待操作的aes加解密单元指针
*/
void subbytes(struct state &w) {
  for (int i = 0; i < 4; ++i) {
    union byteint t = {w.g[i]};
    setbytes(t, sub_bytes(t.t0), sub_bytes(t.t1), sub_bytes(t.t2),
             sub_bytes(t.t3));
    w.g[i] = t.i;
  }
}
/*
rowshift:aes的rowshift操作
w:待操作的aes加解密单元指针
*/
void rowshift(struct state &w) {
  unsigned int t1 = w.g[1], t2 = w.g[2], t3 = w.g[3];
  w.g[1] = rrot(t1, 8);
  w.g[2] = rrot(t2, 16);
  w.g[3] = rrot(t3, 24);
}
/*
columnmix:aes的columnmix操作
w:待操作的aes加解密单元指针
*/
void columnmix(struct state &w) {
  unsigned long long dl = w.datal, dh = w.datah;
  union byteint g0 = {(unsigned int)(dl)}, g1 = {(unsigned int)(dl >> 32)},
                g2 = {(unsigned int)(dh)}, g3 = {(unsigned int)(dh >> 32)};
  for (int i = 0; i < 4; ++i) {
    w.s[0][i] = GMlineA(25, 1, 0, 0);
    w.s[1][i] = GMlineA(0, 25, 1, 0);
    w.s[2][i] = GMlineA(0, 0, 25, 1);
    w.s[3][i] = GMlineA(1, 0, 0, 25);

    g0.i >>= 8, g1.i >>= 8, g2.i >>= 8, g3.i >>= 8;
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