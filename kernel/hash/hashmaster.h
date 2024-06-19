#ifndef HSM
#define HSM

#include "hashbuffer.h"
#include <map>

typedef unsigned char u8_t;
typedef unsigned int u32_t;
typedef unsigned long long u64_t;
// 将x循环左移i位

#define lrot(x, i) (((x) << (i)) | ((x) >> (32 - i)))
// 将x循环右移i位

#define rrot(x, i) (((x) >> (i)) | ((x) << (32 - i)))


#define setbytes(t, b0, b1, b2, b3) \
  t = ((u32_t)b0) | ((u32_t)b1 << 8) | ((u32_t)b2 << 16) | ((u32_t)b3 << 24)
class Hashmaster
{
  u8_t hashblock[64];
  buffer64 *hashbuf;

protected:
  u32_t totalsize;
  /*
  addtotal:累加总长度
  len:长度
  */
  void addtotal(u32_t len) { totalsize += (len << 3); };

  virtual void getHash(const u8_t *input) = 0;
  virtual void getHash(const u8_t *input, u32_t final_loadsize) = 0;
  virtual void reset() = 0;
  virtual void getres(u8_t *hashout) = 0;

public:
  virtual const u8_t gethlen() = 0;
  virtual const u8_t getblen() = 0;
  void getFileHash(buffer64 *buffer, u8_t *hashres);
  void getStringHash(const u8_t *string, u32_t length, u8_t *hashres);
};

class sha1hash : public Hashmaster
{
  u32_t h[5];
  u32_t w[80];
  union
  {
    u8_t s[64];
    u32_t i[16];
  };
  void getwdata();
  void getHash(const u8_t *input);
  void getHash(const u8_t *input, u32_t final_loadsize);
  void reset()
  {
    h[0] = 0x67452301, h[1] = 0xEFCDAB89, h[2] = 0x98BADCFE, h[3] = 0x10325476,
    h[4] = 0xC3D2E1F0;
    totalsize = 0;
  };
  void getres(u8_t *hashout);

public:
  sha1hash() { reset(); };
  virtual const u8_t gethlen() { return 20; };
  virtual const u8_t getblen() { return 64; };
};

class md5hash : public Hashmaster
{
  u32_t h[4];
  union
  {
    u8_t s[64];
    u32_t x[16];
  };
  void getHash(const u8_t *input);
  void getHash(const u8_t *input, u32_t final_loadsize);
  void reset()
  {
    h[0] = 0x67452301, h[1] = 0xEFCDAB89, h[2] = 0x98BADCFE, h[3] = 0x10325476;
    totalsize = 0;
  };
  void getres(u8_t *hashout);

public:
  md5hash() { reset(); };
  virtual const u8_t gethlen() { return 16; };
  virtual const u8_t getblen() { return 64; };
};

class sha256hash : public Hashmaster
{
  static const u32_t k[64];
  u32_t h[8];
  u32_t w[64];
  union
  {
    u8_t s[64];
    u32_t i[16];
  };
  void getwdata();
  void getHash(const u8_t *input);
  void getHash(const u8_t *input, u32_t final_loadsize);
  void reset()
  {
    h[0] = 0x6a09e667;
    h[1] = 0xbb67ae85;
    h[2] = 0x3c6ef372;
    h[3] = 0xa54ff53a;
    h[4] = 0x510e527f;
    h[5] = 0x9b05688c;
    h[6] = 0x1f83d9ab;
    h[7] = 0x5be0cd19;
    totalsize = 0;
  };
  void getres(u8_t *hashout);

public:
  sha256hash() { reset(); };
  virtual const u8_t gethlen() { return 32; };
  virtual const u8_t getblen() { return 64; };
};
/*
哈希函数工厂类
*/
class HashFactory
{
public:
  enum HASH_TYPE
  {
    SHA1,
    MD5,
    SHA256,
    Unknown
  };
  static HASH_TYPE getType(u8_t type);
  Hashmaster *getHasher(HASH_TYPE type);
};
#endif