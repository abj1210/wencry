#ifndef HSM
#define HSM

#include "hashbuffer.h"

typedef unsigned char u8_t;
typedef unsigned int u32_t;
typedef unsigned long long u64_t;
// 将x循环左移i位

#define lrot(x, i) (((x) << (i)) | ((x) >> (32 - i)))
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
  static const u8_t gethlen() { return 0; };
  static const u8_t getblen() { return 0; };
  void getFileHash(FILE *fp, u8_t *hashres);
  void getFileOffsetHash(FILE *fp, u8_t *block, u8_t *hashres);
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
  sha1hash(){reset();};
  static const u8_t gethlen() { return 20; };
  static const u8_t getblen() { return 64; };
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
  md5hash(){reset();};
  static const u8_t gethlen() { return 16; };
  static const u8_t getblen() { return 64; };
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
    Unknown
  };
  static HASH_TYPE getType(u8_t type);
  Hashmaster *getHasher(HASH_TYPE type);
  const u8_t getHashLength(HASH_TYPE type);
  const u8_t getBlkLength(HASH_TYPE type);
};
#endif