#include "aes.h"
#include "macro.h"
#include "tab.h"
/*
subbytes:aes的还原subbytes步骤
*/
void decryaes::subbytes() {
  for (int i = 0; i < 4; ++i) {
    u32_t t = w->g[i];
    setbytes(w->g[i], r_sub_bytes((u8_t)t), r_sub_bytes((u8_t)(t >> 8)),
             r_sub_bytes((u8_t)(t >> 16)), r_sub_bytes((u8_t)(t >> 24)));
  }
}
/*
rowshift:aes的还原rowshift步骤
*/
void decryaes::rowshift() {
  u32_t t1 = w->g[1], t2 = w->g[2], t3 = w->g[3];
  w->g[1] = lrot(t1, 8);
  w->g[2] = lrot(t2, 16);
  w->g[3] = lrot(t3, 24);
}
/*
columnmix:aes的还原columnmix步骤
*/
void decryaes::columnmix() {
  u32_t g0 = w->g[0], g1 = w->g[1], g2 = w->g[2], g3 = w->g[3];
  for (int i = 0; i < 4; ++i) {
    w->s[0][i] = GMlineA(223, 104, 238, 199);
    w->s[1][i] = GMlineA(199, 223, 104, 238);
    w->s[2][i] = GMlineA(238, 199, 223, 104);
    w->s[3][i] = GMlineA(104, 238, 199, 223);
    g0 >>= 8, g1 >>= 8, g2 >>= 8, g3 >>= 8;
  }
}
/*
commonround:aes的一轮解密步骤
round:该操作的轮数
*/
void decryaes::commonround(int round) {
  columnmix();
  rowshift();
  subbytes();
  addroundkey(key.get_key(round));
}
/*
specround:aes的第一轮解密步骤
*/
void decryaes::specround() {
  addroundkey(key.get_key(10));
  rowshift();
  subbytes();
  addroundkey(key.get_key(9));
}
/*
接口函数
decryaes_128bit:将一个128bit的数据块进行aes解密
w:待加解密数据块的地址
*/
void decryaes::decryaes_128bit(state_t *w) {
  this->w = w;
  specround();
  for (int i = 8; i >= 0; --i)
    commonround(i);
  addRBH();
}