#ifndef CRY
#define CRY
#include "multicry.h"
#include "sha1.h"
#include <stdio.h>
typedef unsigned char u8_t;
typedef unsigned long long u64_t;
//魔数
class runcrypt {
  static const u64_t Magic_Num = 0xA5C3A500C3A5C3;
  u8_t tail, state, hash[20];
  FILE *fp, *out;
  u8_t *key;
  void getFileHeader(const u8_t *r_buf);
  void hashfile();
  void checkMn();
  void checkKey();
  void checkFile();

public:
  /*
      构造函数:设定输入输出和密钥
      fp:输入文件指针
      out:输出文件指针
      key:初始密钥序列
  */
  runcrypt(FILE *fp, FILE *out, u8_t *key)
      : fp(fp), out(out), key(key), tail(16), state(0){};
  void enc(const u8_t *r_buf);
  u8_t verify();
  u8_t dec();
};

#endif