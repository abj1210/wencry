#ifndef AES
#define AES

#include "key.h"
#include "util.h"

#include <string.h>
class aeshandle {
protected:
  state_t *w;
  keyhandle *key;
  union {
    u8_t r[0x10];
    u64_t ld[2];
  };
  void addroundkey(const state_t &key);
  void addRBH();

public:
  /*
  构造函数:加载密钥
  key:待加载的密钥
  */
  aeshandle(keyhandle *key, const u8_t *r_hash) : key(key), w(NULL) {
    memcpy(r, r_hash, 16);
  };
};

class encryaes : public aeshandle {
  void subbytes();
  void rowshift();
  void columnmix();
  void commonround(int round);
  void specround();

public:
  encryaes(keyhandle *key, const u8_t *r_hash) : aeshandle(key, r_hash){};
  void encryaes_128bit(state_t *w);
};
class decryaes : public aeshandle {
  void subbytes();
  void rowshift();
  void columnmix();
  void commonround(int round);
  void specround();

public:
  decryaes(keyhandle *key, const u8_t *r_hash) : aeshandle(key, r_hash){};
  void decryaes_128bit(state_t *w);
};

#endif