#include "key.h"
#include "util.h"

#include <stdlib.h>

struct state keyg[11];

/*
genkey:产生每轮的轮密钥
last_key:上一轮的轮密钥
round:本轮的轮数
return:本轮的轮密钥
*/
struct state genkey(struct state last_key, int round) {
  struct state now_key;
  for (int j = 0; j < 4; j++) {
    for (int i = 0; i < 4; i++) {
      if (j == 0) {
        if (i == 0) {
          now_key.s[i][j] =
              (sub_bytes(last_key.s[1][3])) ^ RC[round] ^ last_key.s[i][j];
        } else {
          now_key.s[i][j] =
              (sub_bytes(last_key.s[(i + 1) & 0x3][3])) ^ last_key.s[i][j];
        }
      } else {
        now_key.s[i][j] = now_key.s[i][j - 1] ^ last_key.s[i][j];
      }
    }
  }
  return now_key;
}
/*
接口函数
initgen:产生全部轮密钥
init_key:初始密钥字符串
*/
void initgen(unsigned char *init_key) {
  for (int j = 0; j < 4; j++) {
    for (int i = 0; i < 4; i++) {
      keyg[0].s[i][j] = init_key[(j << 2) | (i & 0x3)];
    }
  }
  for (int i = 1; i < 11; i++)
    keyg[i] = genkey(keyg[i - 1], i);
}
/*
接口函数
gen_key:随机产生一初始密钥
return:产生的初始密钥
*/
unsigned char *gen_key() {
  unsigned char *key = new unsigned char[16];
  for (int i = 0; i < 16; i++) {
    key[i] = rand() & 0xff;
  }
  return key;
}