#ifndef SHA1
#define SHA1

#include "shabuffer.h"
#include <stdio.h>
/*
hash:sha1的hash基本单元
h:20B数据
*/
class sha1hash {
  u32_t h[5];
  /*
  wdata:sha1生成的w数组
  w:320B数据
  */
  typedef struct {
    u32_t w[80];
  } wdata_t;
  wdata_t w;

protected:
  void getwdata(const u8_t *s);
  void gethash();

public:
  sha1hash() {
    h[0] = 0x67452301, h[1] = 0xEFCDAB89, h[2] = 0x98BADCFE, h[3] = 0x10325476,
    h[4] = 0xC3D2E1F0;
  };
  void getres(u8_t *hashout);
  bool cmphash(u8_t *hash);
};
class sha1Filehash : public sha1hash {
  buffer64 ibuf64;

public:
  sha1Filehash(FILE *fp);
};
class sha1Stringhash : public sha1hash {
public:
  sha1Stringhash(const u8_t *s, const u32_t n);
};

#endif