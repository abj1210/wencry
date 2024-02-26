#ifndef CRY
#define CRY
#include "multicry.h"
#include "hashmaster.h"
#include <stdio.h>
typedef unsigned char u8_t;
typedef unsigned long long u64_t;

class hmac {
private:
  static const u8_t ipad = 0x36, opad = 0x5c;
  Hashmaster hashmaster;
  u8_t *hmac_res;
  u8_t getblock(u8_t type);
  u8_t getlength(u8_t type);
  void getres(u8_t *key, FILE *fp);

public:
  /*
  构造函数:设定哈希模式
  */
  hmac(u8_t hashtype) : hashmaster(Hashmaster(Hashmaster::getType(hashtype))) {
    hmac_res = new u8_t[hashmaster.gethlen()];
  };
  ~hmac() { delete[] hmac_res; };
  void gethmac(u8_t *key, FILE *fp, u8_t *hmac_out);
  bool cmphmac(u8_t *key, FILE *fp, const u8_t *hmac_out);
};

//魔数
class runcrypt {
  static const u64_t Magic_Num = 0xA5C3A5C3A5C3A5C3;
  u8_t state, hash[20], iv[multicry_master::THREADS_NUM * 20];
  FILE *fp, *out;
  u8_t *key;
  hmac hmachandle;
  void getFileHeader(const u8_t *r_buf);
  void hashfile();
  void checkMn();
  void checkHmac();

public:
  /*
      构造函数:设定输入输出和密钥
      fp:输入文件指针
      out:输出文件指针
      key:初始密钥序列
  */
  runcrypt(FILE *fp, FILE *out, u8_t *key)
      : fp(fp), out(out), key(key), state(0), hmachandle(0){};
  void enc(const u8_t *r_buf, u8_t ctype);
  u8_t verify();
  u8_t dec(u8_t ctype);
};

#endif