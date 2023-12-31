#include "aes.h"
#include "macro.h"
#include "tab.h"
#include <string.h>
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
