#ifndef AES
#define AES

#include "key.h"
#include "util.h"
class aeshandle {
protected:
  struct state w;
  keyhandle *key;
  void addroundkey(const struct state &key);

public:
  aeshandle(keyhandle *key);
};

class encryaes : public aeshandle {
  void subbytes();
  void rowshift();
  void columnmix();
  void commonround(int round);
  void specround();

public:
  encryaes(keyhandle *key);
  void encryaes_128bit(struct state &w);
};
class decryaes : public aeshandle {
  void subbytes();
  void rowshift();
  void columnmix();
  void commonround(int round);
  void specround();

public:
  decryaes(keyhandle *key);
  void decryaes_128bit(struct state &w);
};

#endif