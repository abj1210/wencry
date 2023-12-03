#ifndef KEY
#define KEY

#include "util.h"
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
  keyhandle();
  keyhandle(const u8_t *b64);
  /*
  get_key:获取相应轮次的密钥
  round:指定的轮次
  return:返回的密钥
  */
  const state_t &get_key(int round) { return key[round]; };
  /*
  接口函数
  get_initkey:返回初始密钥的base64形式
  b64:输出字符串地址
  */
  void get_initkey(u8_t *b64) const { hex_to_base64(init_key, 16, b64); };
  /*
  接口函数
  get_initkey:返回初始密钥
  return:初始密钥
  */
  const u8_t *get_initkey() const { return init_key; };
};

#endif