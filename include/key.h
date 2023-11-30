#ifndef KEY
#define KEY

#include "util.h"
/*
keyhandle:密钥的生成
key:轮密钥数组
init_key:初始密钥序列
*/
class keyhandle {
  struct state key[11];
  unsigned char init_key[20];
  void genkey(int round);
  void genall();

public:
  keyhandle();
  keyhandle(unsigned char *b64);
  struct state &get_key(int round);
  void get_initkey(unsigned char *b64);
  unsigned char *get_initkey();
};

#endif