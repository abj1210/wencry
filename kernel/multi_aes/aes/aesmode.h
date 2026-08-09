#ifndef AMD
#define AMD

//#include "aes.h"
#include "aes_ni.h"
#include <string.h>
#include <string>
#include <stdio.h>
/*
Aesmode:带模式Aes加解密单元
iv:迭代用初始向量
initiv:最初初始向量
*/
class Aesmode
{
protected:
  __m128i iv, initiv;

public:
  Aesmode(const u8_t *iv){
    this->iv = _mm_loadu_si128((const __m128i*)iv);
    this->initiv = _mm_loadu_si128((const __m128i*)iv);
  };
  virtual ~Aesmode() {};
  /*
  runcry:加解密方法
  block:加密块
  */
  virtual void runcry(u8_t *block) = 0;
};
/*
Aes加密工厂类
*/
class AesFactory {
  u8_t * key;
  const u8_t *iv;
public:
  AesFactory(u8_t *key): key(key) {};
  AesFactory(u8_t *key, const u8_t * iv): key(key), iv(iv) {};
  static std::string getName(u8_t type);
  void loadiv(const u8_t * iv){this->iv = iv;};
  Aesmode * createCryMaster(bool isenc, u8_t type);
  Aesmode * createCryMaster(bool isenc, u8_t type, const u8_t * iv);
};

#endif
