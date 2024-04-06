#ifndef HTP
#define HTP

#include "hashbuffer.h"
#include <stdio.h>

typedef unsigned char u8_t;
typedef unsigned int u32_t;
typedef unsigned long long u64_t;
//将x循环左移i位

#define lrot(x, i) (((x) << (i)) | ((x) >> (32 - i)))
#define setbytes(t, b0, b1, b2, b3)                                            \
  t = ((u32_t)b0) | ((u32_t)b1 << 8) | ((u32_t)b2 << 16) | ((u32_t)b3 << 24)
/*
typehash:哈希函数抽象类
*/
class typehash {
  const u8_t blocklength, hashlength;

protected:
  u32_t totalsize;
  /*
  addtotal:累加总长度
  len:长度
  */
  void addtotal(u32_t len) { totalsize += (len << 3); };

public:
  typehash(u8_t blocklength, u8_t hashlength)
      : blocklength(blocklength), hashlength(hashlength){};
  u8_t getblen() { return blocklength; };
  u8_t gethlen() { return hashlength; };
  virtual void gethash() = 0;
  virtual u8_t *getLoadAddr() = 0;
  virtual void finalHash(u32_t loadsize) = 0;
  virtual void reset() = 0;
  virtual void getres(u8_t *hashout) = 0;
};

/*
hash:sha1的hash基本单元
*/
class sha1hash : public typehash {
  u32_t h[5];
  u32_t w[80];
  union {
    u8_t s[64];
    u32_t i[16];
  };
  void getwdata();

public:
  /*
    构造函数:设定哈希初值
  */
  sha1hash() : typehash(64, 20) { reset(); };
  void gethash();
  u8_t *getLoadAddr();
  void finalHash(u32_t loadsize);
  void reset() {
    h[0] = 0x67452301, h[1] = 0xEFCDAB89, h[2] = 0x98BADCFE, h[3] = 0x10325476,
    h[4] = 0xC3D2E1F0;
    totalsize = 0;
  };
  void getres(u8_t *hashout);
};

class md5hash : public typehash {
  u32_t h[4];
  union {
    u8_t s[64];
    u32_t x[16];
  };
public:
  /*
    构造函数:设定哈希初值
  */
  md5hash() : typehash(64, 16){ reset(); };
  void gethash();
  u8_t *getLoadAddr();
  void finalHash(u32_t loadsize);
  void reset() {
    h[0] = 0x67452301, h[1] = 0xEFCDAB89, h[2] = 0x98BADCFE, h[3] = 0x10325476;
    totalsize = 0;
  };
  void getres(u8_t *hashout);
};
#endif