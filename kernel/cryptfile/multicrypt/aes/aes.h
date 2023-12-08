#ifndef AES
#define AES

#include "state.h"
#include <string.h>
class aeshandle {
protected:
  state_t *w;
  /*
  keyhandle:密钥的生成
  key:轮密钥
  init_key:初始密钥序列
  */
  class keyhandle {
    state_t key[11];
    u8_t init_key[20];
    void genkey(int round);
    void genall();

  public:
    keyhandle(const u8_t *initkey);
    /*
    get_key:获取相应轮次的密钥
    round:指定的轮次
    return:返回的密钥
    */
    const state_t &get_key(int round) { return key[round]; };
  } key;
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
  aeshandle(const u8_t *initkey, const u8_t *r_hash) : key(initkey), w(NULL) {
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
  encryaes(const u8_t *initkey, const u8_t *r_hash)
      : aeshandle(initkey, r_hash){};
  void encryaes_128bit(state_t *w);
};
class decryaes : public aeshandle {
  void subbytes();
  void rowshift();
  void columnmix();
  void commonround(int round);
  void specround();

public:
  decryaes(const u8_t *initkey, const u8_t *r_hash)
      : aeshandle(initkey, r_hash){};
  void decryaes_128bit(state_t *w);
};

#endif