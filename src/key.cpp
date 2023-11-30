#include "key.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>

extern void hex_to_base64(unsigned char *hex_in, int len,
                          unsigned char *base64_out);
extern void base64_to_hex(unsigned char *base64_in, int len,
                          unsigned char *hex_out);
/*
构造函数:产生随机密钥
*/
keyhandle::keyhandle() {
  for (int i = 0; i < 16; ++i)
    init_key[i] = rand() & 0xff;
  genall();
}
/*
构造函数:产生指定密钥
b64:指定密钥的base64编码形式
*/
keyhandle::keyhandle(unsigned char *b64) {
  base64_to_hex(b64, strlen((const char *)b64), init_key);
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
/*
get_key:获取相应轮次的密钥
round:指定的轮次
return:返回的密钥
*/
struct state &keyhandle::get_key(int round) {
  return key[round];
}
/*
接口函数
get_initkey:返回初始密钥的base64形式
b64:输出字符串地址
*/
void keyhandle::get_initkey(unsigned char *b64) {
  hex_to_base64(init_key, 16, b64);
}
/*
接口函数
get_initkey:返回初始密钥
return:初始密钥
*/
unsigned char *keyhandle::get_initkey() { return init_key; }