#include "aesmode.h"

/*################################
  AES算法子类实现
################################*/

/*
getXor:获取异或值
x:被异或值
mask:异或掩码
*/
void Aesmode::getXor(u8_t *x, u8_t *mask)
{
  for (int i = 0; i < 4; ++i)
    *(((u32_t *)x) + i) ^= *(((u32_t *)mask) + i);
}

class AesEncrypt : public Aesmode
{
protected:
  encryaes crypt;

public:
  AesEncrypt(u8_t *key, const u8_t *iv) : Aesmode(iv), crypt(key){};
};

class AesDecrypt : public Aesmode
{
protected:
  decryaes crypt;

public:
  AesDecrypt(u8_t *key, const u8_t *iv) : Aesmode(iv), crypt(key){};
};

class AesECB_Enc : public AesEncrypt
{
public:
  AesECB_Enc(u8_t *key, const u8_t *iv) : AesEncrypt(key, iv){};
  virtual void runcry(u8_t *block) override { crypt.runaes_128bit(block); };
};

class AesECB_Dec : public AesDecrypt
{
public:
  AesECB_Dec(u8_t *key, const u8_t *iv) : AesDecrypt(key, iv){};
  virtual void runcry(u8_t *block) override { crypt.runaes_128bit(block); };
};

class AesCBC_Enc : public AesEncrypt
{
public:
  AesCBC_Enc(u8_t *key, const u8_t *iv) : AesEncrypt(key, iv){};
  virtual void runcry(u8_t *block) override
  {
    getXor(block, iv);
    crypt.runaes_128bit(block);
    memcpy(iv, block, 16);
  }
};

class AesCBC_Dec : public AesDecrypt
{
public:
  AesCBC_Dec(u8_t *key, const u8_t *iv) : AesDecrypt(key, iv){};
  virtual void runcry(u8_t *block) override
  {
    u8_t nxt_iv[16];
    memcpy(nxt_iv, block, 16);
    crypt.runaes_128bit(block);
    getXor(block, iv);
    memcpy(iv, nxt_iv, 16);
  }
};

class AesCTR : public AesEncrypt
{
  void ctrInc()
  {
    for (int i = 15; i >= 0; i--)
    {
      iv[i]++;
      if (iv[i] != 0)
        break;
    }
  }

public:
  AesCTR(u8_t *key, const u8_t *iv) : AesEncrypt(key, iv){};
  virtual void runcry(u8_t *block) override
  {
    u8_t mask[16];
    memcpy(mask, iv, 16);
    crypt.runaes_128bit(mask);
    getXor(block, mask);
    ctrInc();
  }
};

class AesCFB_Enc : public AesEncrypt
{
public:
  AesCFB_Enc(u8_t *key, const u8_t *iv) : AesEncrypt(key, iv){};
  virtual void runcry(u8_t *block) override
  {
    crypt.runaes_128bit(iv);
    getXor(block, iv);
    memcpy(iv, block, 16);
  }
};

class AesCFB_Dec : public AesEncrypt
{
public:
  AesCFB_Dec(u8_t *key, const u8_t *iv) : AesEncrypt(key, iv){};
  virtual void runcry(u8_t *block) override
  {
    u8_t nxt_iv[16];
    memcpy(nxt_iv, block, 16);
    crypt.runaes_128bit(iv);
    getXor(block, iv);
    memcpy(iv, nxt_iv, 16);
  }
};

class AesOFB : public AesEncrypt
{
public:
  AesOFB(u8_t *key, const u8_t *iv) : AesEncrypt(key, iv){};
  virtual void runcry(u8_t *block) override
  {
    crypt.runaes_128bit(iv);
    getXor(block, iv);
  }
};

/*################################
  AES工厂函数
################################*/

/*
createEncryMaster:返回相应的加密器
isenc:是否为加密
type:类型(0:ECB,1:CBC,2:CTR,3:CFB,4:OFB)
return:返回的加密器
*/
Aesmode *AesFactory::createCryMaster(bool isenc, u8_t type)
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