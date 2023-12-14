#ifndef SHA1
#define SHA1

#include "shabuffer.h"
#include <stdio.h>

typedef unsigned char u8_t;
typedef unsigned int u32_t;
typedef unsigned long long u64_t;
//将x循环左移i位

#define lrot(x, i) (((x) << (i)) | ((x) >> (32 - i)))
#define setbytes(t, b0, b1, b2, b3)                                            \
  t = ((u32_t)b0) | ((u32_t)b1 << 8) | ((u32_t)b2 << 16) | ((u32_t)b3 << 24)

/*
hash:sha1的hash基本单元
h:20B数据
*/
class sha1hash {
  u32_t h[2][5];
  u32_t turn;
  u32_t w[80];
  union {
    u8_t s[64];
    u32_t i[16];
  };
  void getwdata();

protected:
  u32_t totalsize;
  void gethash();
  u8_t *getLoadAddr();
  void finalHash(u32_t loadsize);

public:
  /*
    构造函数:设定哈希初值
  */
  sha1hash() : turn(0), totalsize(0) {
    h[0][0] = 0x67452301, h[0][1] = 0xEFCDAB89, h[0][2] = 0x98BADCFE,
    h[0][3] = 0x10325476, h[0][4] = 0xC3D2E1F0;
  };
  void getres(u8_t *hashout);
  bool cmphash(u8_t *hash) const;
};
class sha1Filehash : public sha1hash {
  buffer64 *ibuf64;

public:
  sha1Filehash(FILE *fp);
  ~sha1Filehash() { delete ibuf64; };
};
class sha1Stringhash : public sha1hash {
public:
  sha1Stringhash(const u8_t *s, const u32_t n);
};

#endif