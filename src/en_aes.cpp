#include "aes.h"
#include "util.h"
/*
addroundkey:aes的密钥轮加操作
key:相应的轮密钥指针
*/
void aeshandle::addroundkey(const state_t &key) {
  w.datal ^= key.datal;
  w.datah ^= key.datah;
}
/*
subbytes:aes的subbytes操作
*/
void encryaes::subbytes() {
  for (int i = 0; i < 4; ++i) {
    u32_t t = w.g[i];
    setbytes(w.g[i], sub_bytes((u8_t)t), sub_bytes((u8_t)(t >> 8)),
             sub_bytes((u8_t)(t >> 16)), sub_bytes((u8_t)(t >> 24)));
  }
}
/*
rowshift:aes的rowshift操作
*/
void encryaes::rowshift() {
  u32_t t1 = w.g[1], t2 = w.g[2], t3 = w.g[3];
  w.g[1] = rrot(t1, 8);
  w.g[2] = rrot(t2, 16);
  w.g[3] = rrot(t3, 24);
}
/*
columnmix:aes的columnmix操作
*/
void encryaes::columnmix() {
  u32_t g0 = w.g[0], g1 = w.g[1], g2 = w.g[2], g3 = w.g[3];
  for (int i = 0; i < 4; ++i) {
    w.s[0][i] = GMlineA(25, 1, 0, 0);
    w.s[1][i] = GMlineA(0, 25, 1, 0);
    w.s[2][i] = GMlineA(0, 0, 25, 1);
    w.s[3][i] = GMlineA(1, 0, 0, 25);
    g0 >>= 8, g1 >>= 8, g2 >>= 8, g3 >>= 8;
  }
}
/*
commonround:aes的一轮加密步骤
round:该操作的轮数
*/
void encryaes::commonround(int round) {
  addroundkey(key->get_key(round));
  subbytes();
  rowshift();
  columnmix();
}
/*
specround:aes的最后一轮加密步骤
*/
void encryaes::specround() {
  addroundkey(key->get_key(9));
  subbytes();
  rowshift();
  addroundkey(key->get_key(10));
}
/*
接口函数
encryaes_128bit:将一个128bit的数据块进行aes加密
w:待加解密数据块的地址
*/
void encryaes::encryaes_128bit(state_t &w) {
  this->w = w;
  for (int i = 0; i < 9; ++i)
    commonround(i);
  specround();
}