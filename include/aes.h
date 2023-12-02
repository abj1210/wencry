#ifndef AES
#define AES

#include "key.h"
#include "util.h"
class aeshandle {
protected:
  state_t w;
  keyhandle *key;
  void addroundkey(const state_t &key);

public:
  /*
  构造函数:加载密钥
  key:待加载的密钥
  */
  aeshandle(keyhandle *key) : key(key){};
};

class encryaes : public aeshandle {
  void subbytes();
  void rowshift();
  void columnmix();
  void commonround(int round);
  void specround();

public:
  encryaes(keyhandle *key) : aeshandle(key){};
  void encryaes_128bit(state_t &w);
};
class decryaes : public aeshandle {
  void subbytes();
  void rowshift();
  void columnmix();
  void commonround(int round);
  void specround();

public:
  decryaes(keyhandle *key) : aeshandle(key){};
  void decryaes_128bit(state_t &w);
};

#endif