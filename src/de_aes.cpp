#include "aes.h"
#include "Autil.h"

extern struct state keyg[11];
extern void addroundkey(struct state &w, const struct state &key);
/*
resubbytes:aes的还原subbytes步骤
w:待操作的aes加解密单元指针
*/
void resubbytes(struct state &w) {
  for (int i = 0; i < 4; ++i) {
    union byteint t = {w.g[i]};
    setbytes(t, r_sub_bytes(t.t0), r_sub_bytes(t.t1), r_sub_bytes(t.t2),
             r_sub_bytes(t.t3));
    w.g[i] = t.i;
  }
}
/*
rerowshift:aes的还原rowshift步骤
w:待操作的aes加解密单元指针
*/
void rerowshift(struct state &w) {
  unsigned int t1 = w.g[1], t2 = w.g[2], t3 = w.g[3];
  w.g[1] = lrot(t1, 8);
  w.g[2] = lrot(t2, 16);
  w.g[3] = lrot(t3, 24);
}
/*
recolumnmix:aes的还原columnmix步骤
w:待操作的aes加解密单元指针
*/
void recolumnmix(struct state &w) {
  unsigned long long dl = w.datal, dh = w.datah;
  union byteint g0 = {(unsigned int)(dl)}, g1 = {(unsigned int)(dl >> 32)},
                g2 = {(unsigned int)(dh)}, g3 = {(unsigned int)(dh >> 32)};
  for (int i = 0; i < 4; ++i) {
    w.s[0][i] = GMlineA(223, 104, 238, 199);
    w.s[1][i] = GMlineA(199, 223, 104, 238);
    w.s[2][i] = GMlineA(238, 199, 223, 104);
    w.s[3][i] = GMlineA(104, 238, 199, 223);

    g0.i >>= 8, g1.i >>= 8, g2.i >>= 8, g3.i >>= 8;
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