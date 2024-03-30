#include "aes.h"
#include "tab.h"
/*################################
  密钥函数
################################*/
/*
构造函数:产生指定密钥
initkey:指定密钥
*/
aeshandle::keyhandle::keyhandle(const u8_t *initkey) {
  memcpy(init_key, initkey, 16);
  genall();
}
/*
genkey:产生每轮的轮密钥
round:本轮的轮数
*/
void aeshandle::keyhandle::genkey(int round) {
  for (int j = 0; j < 4; ++j)
    for (int i = 0; i < 4; ++i)
      if (j == 0)
        if (i == 0)
          key[round].s[i][j] = (s_box[key[round - 1].s[1][3]]) ^ RC[round] ^
                               key[round - 1].s[i][j];
        else
          key[round].s[i][j] = (s_box[key[round - 1].s[(i + 1) & 0x3][3]]) ^
                               key[round - 1].s[i][j];
      else
        key[round].s[i][j] = key[round].s[i][j - 1] ^ key[round - 1].s[i][j];
}
/*
genall:产生全部密钥
*/
void aeshandle::keyhandle::genall() {
  for (int j = 0; j < 4; ++j)
    for (int i = 0; i < 4; ++i)
      key[0].s[i][j] = init_key[(j << 2) | (i & 0x3)];
  for (int i = 1; i < 11; ++i)
    genkey(i);
}


/*################################
  加密辅助函数
################################*/
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
    setbytes(w.g[i], s_box[(u8_t)t], s_box[(u8_t)(t >> 8)],
             s_box[(u8_t)(t >> 16)], s_box[(u8_t)(t >> 24)]);
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
    w.s[0][i] = GMumLine(25, 1, 0, 0);
    w.s[1][i] = GMumLine(0, 25, 1, 0);
    w.s[2][i] = GMumLine(0, 0, 25, 1);
    w.s[3][i] = GMumLine(1, 0, 0, 25);
    g0 >>= 8, g1 >>= 8, g2 >>= 8, g3 >>= 8;
  }
}
/*
commonround:aes的一轮加密步骤
round:该操作的轮数
*/
inline void encryaes::commonround(int round) {
  addroundkey(key.get_key(round));
  subbytes();
  rowshift();
  columnmix();
}
/*
specround:aes的最后一轮加密步骤
*/
inline void encryaes::specround() {
  addroundkey(key.get_key(9));
  subbytes();
  rowshift();
  addroundkey(key.get_key(10));
}


/*################################
  解密辅助函数
################################*/
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


/*################################
  接口函数
################################*/
/*
encryaes_128bit:将一个128bit的数据块进行aes加密
w:待加解密数据块的地址
*/
void encryaes::runaes_128bit(u8_t *w) {
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      this->w.s[i][j] = w[(j << 2) + i];
    }
  }
  for (int i = 0; i < 9; ++i)
    commonround(i);
  specround();
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      w[(j << 2) + i] = this->w.s[i][j];
    }
  }
}
/*
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