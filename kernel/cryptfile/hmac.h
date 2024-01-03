#ifndef HMC
#define HMC

#include "hashmaster.h"
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

#endif