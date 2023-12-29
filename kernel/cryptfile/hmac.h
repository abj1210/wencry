#ifndef HMC
#define HMC

#include "sha1.h"
class hmac {
private:
  static const u8_t ipad = 0x36, opad = 0x5c;
  const u8_t block, length;
  u8_t *hmac_res;
  u8_t getblock(u8_t type);
  u8_t getlength(u8_t type);
  void getres(u8_t *key, FILE *fp);

public:
  /*
  构造函数:设定哈希模式
  */
  hmac(u8_t hashtype) : block(getblock(hashtype)), length(getlength(hashtype)) {
    hmac_res = new u8_t[length];
  };
  ~hmac() { delete[] hmac_res; };
  void gethmac(u8_t *key, FILE *fp, u8_t *hmac_out);
  bool cmphmac(u8_t *key, FILE *fp, const u8_t *hmac_out);
};

#endif