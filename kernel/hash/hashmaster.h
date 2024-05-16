#ifndef HSM
#define HSM

#include "hashbuffer.h"
#include "hashtype.h"
class Hashmaster
{
public:
  enum HASH_TYPE
  {
    SHA1,
    MD5,
    Unknown
  };

private:
  HASH_TYPE type;
  u8_t hashblock[64];
  typehash *hasher;
  buffer64 *hashbuf;

public:
  Hashmaster(HASH_TYPE type);
  ~Hashmaster() { delete hasher; };
  static HASH_TYPE getType(u8_t type);
  u8_t gethlen() { return hasher->gethlen(); };
  u8_t getblen() { return hasher->getblen(); };
  void getFileHash(FILE *fp, u8_t *hashres);
  void getFileOffsetHash(FILE *fp, u8_t *block, u8_t *hashres);
  void getStringHash(const u8_t *string, u32_t length, u8_t *hashres);
};
#endif