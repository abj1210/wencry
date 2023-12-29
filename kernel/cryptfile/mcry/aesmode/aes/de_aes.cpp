#include "aes.h"
#include "macro.h"
#include "tab.h"
/*
subbytes:aes的还原subbytes步骤
*/
void decryaes::subbytes() {
  for (int i = 0; i < 4; ++i) {
    u32_t t = w.g[i];
    setbytes(w.g[i], rs_box[(u8_t)t], rs_box[(u8_t)(t >> 8)],
             rs_box[(u8_t)(t >> 16)], rs_box[(u8_t)(t >> 24)]);
  }
}
/*
rowshift:aes的还原rowshift步骤
*/
void decryaes::rowshift() {
  u32_t t1 = w.g[1], t2 = w.g[2], t3 = w.g[3];
  w.g[1] = lrot(t1, 8);
  w.g[2] = lrot(t2, 16);
  w.g[3] = lrot(t3, 24);
}
/*
columnmix:aes的还原columnmix步骤
*/
void decryaes::columnmix() {
  u32_t g0 = w.g[0], g1 = w.g[1], g2 = w.g[2], g3 = w.g[3];
  for (int i = 0; i < 4; ++i) {
    w.s[0][i] = GMumLine(223, 104, 238, 199);
    w.s[1][i] = GMumLine(199, 223, 104, 238);
    w.s[2][i] = GMumLine(238, 199, 223, 104);
    w.s[3][i] = GMumLine(104, 238, 199, 223);
    g0 >>= 8, g1 >>= 8, g2 >>= 8, g3 >>= 8;
  }
}
/*
commonround:aes的一轮解密步骤
round:该操作的轮数
*/
inline void decryaes::commonround(int round) {
  columnmix();
  rowshift();
  subbytes();
  addroundkey(key.get_key(round));
}
/*
specround:aes的第一轮解密步骤
*/
inline void decryaes::specround() {
  addroundkey(key.get_key(10));
  rowshift();
  subbytes();
  addroundkey(key.get_key(9));
}
/*
接口函数
runaes_128bit:将一个128bit的数据块进行aes解密
w:待加解密数据块的地址
*/
void decryaes::runaes_128bit(u8_t *w) {
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      this->w.s[i][j] = w[(j << 2) + i];
    }
  }
  specround();
  for (int i = 8; i >= 0; --i)
    commonround(i);
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      w[(j << 2) + i] = this->w.s[i][j];
    }
  }
}