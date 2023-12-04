#include "key.h"
#include <stdlib.h>
#include <string.h>
/*
构造函数:产生随机密钥
*/
keyhandle::keyhandle() {
  for (int i = 0; i < 16; ++i)
    init_key[i] = rand();
  genall();
}
/*
构造函数:产生指定密钥
b64:指定密钥的base64编码形式
*/
keyhandle::keyhandle(const u8_t *b64) {
  base64_to_hex(b64, 24, init_key);
  genall();
}
/*
genkey:产生每轮的轮密钥
round:本轮的轮数
*/
void keyhandle::genkey(int round) {
  for (int j = 0; j < 4; ++j)
    for (int i = 0; i < 4; ++i)
      if (j == 0)
        if (i == 0)
          key[round].s[i][j] = (sub_bytes(key[round - 1].s[1][3])) ^ RC[round] ^
                               key[round - 1].s[i][j];
        else
          key[round].s[i][j] = (sub_bytes(key[round - 1].s[(i + 1) & 0x3][3])) ^
                               key[round - 1].s[i][j];
      else
        key[round].s[i][j] = key[round].s[i][j - 1] ^ key[round - 1].s[i][j];
}
/*
genall:产生全部密钥
*/
void keyhandle::genall() {
  for (int j = 0; j < 4; ++j)
    for (int i = 0; i < 4; ++i)
      key[0].s[i][j] = init_key[(j << 2) | (i & 0x3)];
  for (int i = 1; i < 11; ++i)
    genkey(i);
}
