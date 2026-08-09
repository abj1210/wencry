#include "aesmode.h"

/*################################
  AES算法子类实现
################################*/

class AesEncrypt : public Aesmode
{
protected:
  EncryAes crypt;

public:
  AesEncrypt(u8_t *key, const u8_t *iv) : Aesmode(iv), crypt(key){};
};

class AesDecrypt : public Aesmode
{
protected:
  DecryAes crypt;

public:
  AesDecrypt(u8_t *key, const u8_t *iv) : Aesmode(iv), crypt(key){};
};

class AesECB_Enc : public AesEncrypt
{
public:
  AesECB_Enc(u8_t *key, const u8_t *iv) : AesEncrypt(key, iv){};
  virtual void runcry(u8_t *block) override { 
    __m128i s = _mm_loadu_si128((const __m128i*)block); 
    s = crypt.runaes_128bit(s); 
    _mm_storeu_si128((__m128i*)block, s);
  };
};

class AesECB_Dec : public AesDecrypt
{
public:
  AesECB_Dec(u8_t *key, const u8_t *iv) : AesDecrypt(key, iv){};
  virtual void runcry(u8_t *block) override { 
    __m128i s = _mm_loadu_si128((const __m128i*)block); 
    s = crypt.runaes_128bit(s); 
    _mm_storeu_si128((__m128i*)block, s);
   };
};

class AesCBC_Enc : public AesEncrypt
{
public:
  AesCBC_Enc(u8_t *key, const u8_t *iv) : AesEncrypt(key, iv){};
  virtual void runcry(u8_t *block) override
  {
    __m128i s = _mm_loadu_si128((const __m128i*)block); 
    s = _mm_xor_si128(s, iv);
    iv = crypt.runaes_128bit(s);
    _mm_storeu_si128((__m128i*)block, iv);
  }
};

class AesCBC_Dec : public AesDecrypt
{
public:
  AesCBC_Dec(u8_t *key, const u8_t *iv) : AesDecrypt(key, iv){};
  virtual void runcry(u8_t *block) override
  {
    __m128i nxt_iv = _mm_loadu_si128((const __m128i*)block); 
    __m128i s = crypt.runaes_128bit(nxt_iv);
    s = _mm_xor_si128(s, iv);
    iv = nxt_iv;
    _mm_storeu_si128((__m128i*)block, s);
  }
};

class AesCTR : public AesEncrypt
{
  void ctrInc()
  {
    u8_t ivb[16];
    _mm_storeu_si128((__m128i*)ivb, iv);
    for (int i = 15; i >= 0; i--)
    {
      ivb[i]++;
      if (ivb[i] != 0)
        break;
    }
    iv = _mm_loadu_si128((const __m128i*)ivb);
  }
public:
  AesCTR(u8_t *key, const u8_t *iv) : AesEncrypt(key, iv){};
  virtual void runcry(u8_t *block) override
  {
    __m128i s = _mm_loadu_si128((const __m128i*)block); 
    __m128i mask = crypt.runaes_128bit(iv);
    s = _mm_xor_si128(s, mask);
    ctrInc();
    _mm_storeu_si128((__m128i*)block, s);
  }
};

class AesCFB_Enc : public AesEncrypt
{
public:
  AesCFB_Enc(u8_t *key, const u8_t *iv) : AesEncrypt(key, iv){};
  virtual void runcry(u8_t *block) override
  {
    __m128i s = _mm_loadu_si128((const __m128i*)block);
    iv = crypt.runaes_128bit(iv);
    iv = _mm_xor_si128(s, iv);
    _mm_storeu_si128((__m128i*)block, iv);
  }
};

class AesCFB_Dec : public AesEncrypt
{
public:
  AesCFB_Dec(u8_t *key, const u8_t *iv) : AesEncrypt(key, iv){};
  virtual void runcry(u8_t *block) override
  {
    __m128i nxt_iv = _mm_loadu_si128((const __m128i*)block);
    iv = crypt.runaes_128bit(iv);
    __m128i s = _mm_xor_si128(nxt_iv, iv);
    iv=nxt_iv;
    _mm_storeu_si128((__m128i*)block, s);
  }
};

class AesOFB : public AesEncrypt
{
public:
  AesOFB(u8_t *key, const u8_t *iv) : AesEncrypt(key, iv){};
  virtual void runcry(u8_t *block) override
  {
    __m128i s = _mm_loadu_si128((const __m128i*)block);
    iv = crypt.runaes_128bit(iv);
    s = _mm_xor_si128(s, iv);
    _mm_storeu_si128((__m128i*)block, s);
  }
};

/*################################
  AES工厂函数
################################*/

/*
createCryMaster:返回相应的加密器
isenc:是否为加密
type:类型(0:ECB,1:CBC,2:CTR,3:CFB,4:OFB)
iv:初始向量
return:返回的加密器
*/
Aesmode *AesFactory::createCryMaster(bool isenc, u8_t type, const u8_t *iv)
{
  if (isenc)
  {
    switch (type)
    {
    case 0:
      return new AesECB_Enc(key, iv);
    case 1:
      return new AesCBC_Enc(key, iv);
    case 2:
      return new AesCTR(key, iv);
    case 3:
      return new AesCFB_Enc(key, iv);
    case 4:
      return new AesOFB(key, iv);
    default:
      return NULL;
    }
  }
  else
  {
    switch (type)
    {
    case 0:
      return new AesECB_Dec(key, iv);
    case 1:
      return new AesCBC_Dec(key, iv);
    case 2:
      return new AesCTR(key, iv);
    case 3:
      return new AesCFB_Dec(key, iv);
    case 4:
      return new AesOFB(key, iv);
    default:
      return NULL;
    }
  }
}
Aesmode *AesFactory::createCryMaster(bool isenc, u8_t type)
{
  return createCryMaster(isenc, type, iv);
}
/*
getName:获取模式名称
type:模式码
return:模式名称
*/
std::string AesFactory::getName(u8_t type){
  switch (type)
  {
  case 0:
    return "ECB";
  case 1:
    return "CBC";
  case 2:
    return "CTR";
  case 3:
    return "CFB";
  case 4:
    return "OFB";
  default:
    return "Unknown";
  }
}