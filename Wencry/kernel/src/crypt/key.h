#ifndef KEY
#define KEY

#include "kutil.h"
/*
keyhandle:密钥的生成
key:轮密钥数组
init_key:初始密钥序列
*/
class keyhandle {
  state_t key[11];
  u8_t init_key[20];
  void genkey(int round);
  void genall();

public:
  keyhandle(const u8_t *initkey);
  /*
  get_key:获取相应轮次的密钥
  round:指定的轮次
  return:返回的密钥
  */
  const state_t &get_key(int round) { return key[round]; };
};

#endif