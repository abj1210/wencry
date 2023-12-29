#ifndef AES
#define AES

#include "state.h"
class aeshandle {
protected:
  state_t w;
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
  void addroundkey(const state_t &key);

public:
  /*
  构造函数:加载密钥
  key:待加载的密钥
  */
  aeshandle(const u8_t *initkey) : key(initkey){};
  virtual void runaes_128bit(u8_t *w) = 0;
};
class encryaes : public aeshandle {
  void subbytes();
  void rowshift();
  void columnmix();
  inline void commonround(int round);
  inline void specround();

public:
  encryaes(const u8_t *initkey) : aeshandle(initkey){};
  void runaes_128bit(u8_t *w);
};
class decryaes : public aeshandle {
  void subbytes();
  void rowshift();
  void columnmix();
  inline void commonround(int round);
  inline void specround();

public:
  decryaes(const u8_t *initkey) : aeshandle(initkey){};
  void runaes_128bit(u8_t *w);
};

#endif