#ifndef AMD
#define AMD

#include "aes.h"
#include <string.h>

class Aesmode {
protected:
  encryaes encryhandle;
  decryaes decryhandle;
  u8_t iv[16];
  u8_t initiv[16];
  void getXor(u8_t *x, u8_t *mask);

public:
  Aesmode(u8_t *key) : encryhandle(key), decryhandle(key) {};
  Aesmode(u8_t *key, const u8_t *iv) : encryhandle(key), decryhandle(key) {
    memcpy(initiv, iv, 16);
    resetIV();
  };
  /*
  resetIV:重设初始向量
  */
  void resetIV(u8_t *iv) {memcpy(initiv, iv, 16);resetIV();};
  void resetIV() { memcpy(iv, initiv, 16); };
  /*
  getencry:加密方法
  block:加密块
  */
  virtual void getencry(u8_t *block) = 0;
  /*
  getencry:解密方法
  block:加密块
  */
  virtual void getdecry(u8_t *block) = 0;
};

class AesECB : public Aesmode {
public:
  AesECB(u8_t *key, const u8_t *iv) : Aesmode(key, iv){};
  virtual void getencry(u8_t *block) { encryhandle.runaes_128bit(block); };
  virtual void getdecry(u8_t *block) { decryhandle.runaes_128bit(block); };
};

class AesCBC : public Aesmode {
public:
  AesCBC(u8_t *key, const u8_t *iv) : Aesmode(key, iv){};
  virtual void getencry(u8_t *block);
  virtual void getdecry(u8_t *block);
};

class AesCTR : public Aesmode {
  void ctrInc();

public:
  AesCTR(u8_t *key, const u8_t *iv) : Aesmode(key, iv){};
  virtual void getencry(u8_t *block);
  virtual void getdecry(u8_t *block) { getencry(block); };
};

class AesCFB : public Aesmode {
public:
  AesCFB(u8_t *key, const u8_t *iv) : Aesmode(key, iv){};
  virtual void getencry(u8_t *block);
  virtual void getdecry(u8_t *block);
};

class AesOFB : public Aesmode {
public:
  AesOFB(u8_t *key, const u8_t *iv) : Aesmode(key, iv){};
  virtual void getencry(u8_t *block);
  virtual void getdecry(u8_t *block) { getencry(block); };
};
Aesmode *selectCryptMode(u8_t *key, const u8_t *iv, u8_t type);

#endif
