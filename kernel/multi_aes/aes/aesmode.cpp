#include "aesmode.h"

/*################################
  AES算法子类实现
  每种模式实现 Aesmode::runcry(对单个16字节块原地加解密),
  并维护各自的 IV/计数器状态(iv 成员,线程独占)。
################################*/

/* 加密单元基类:持有 AES-NI 加密器 */
class AesEncrypt : public Aesmode
{
protected:
  EncryAes crypt;

public:
  AesEncrypt(u8_t *key, const u8_t *iv) : Aesmode(iv), crypt(key){};
};

/* 解密单元基类:持有 AES-NI 解密器 */
class AesDecrypt : public Aesmode
{
protected:
  DecryAes crypt;

public:
  AesDecrypt(u8_t *key, const u8_t *iv) : Aesmode(iv), crypt(key){};
};

/*
ECB 加密:块之间相互独立,不使用 IV。
C = E(P)            (每块独立)
*/
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

/*
ECB 解密:P = D(C)
*/
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

/*
CBC 加密:C = E(P ^ IV_prev),IV_prev 逐块更新为上一块密文。
块间串行依赖,属于链式模式。
*/
class AesCBC_Enc : public AesEncrypt
{
public:
  AesCBC_Enc(u8_t *key, const u8_t *iv) : AesEncrypt(key, iv){};
  virtual void runcry(u8_t *block) override
  {
    __m128i s = _mm_loadu_si128((const __m128i*)block);
    s = _mm_xor_si128(s, iv);              // 明文与上一块密文(或初始IV)异或
    iv = crypt.runaes_128bit(s);           // 加密,结果作为下一块的IV
    _mm_storeu_si128((__m128i*)block, iv);
  }
};

/*
CBC 解密:P = D(C) ^ IV_prev。
先保存当前密文作为下一块IV,再解密并与上一块密文异或。
*/
class AesCBC_Dec : public AesDecrypt
{
public:
  AesCBC_Dec(u8_t *key, const u8_t *iv) : AesDecrypt(key, iv){};
  virtual void runcry(u8_t *block) override
  {
    __m128i nxt_iv = _mm_loadu_si128((const __m128i*)block); // 本块密文,稍后作为下一块IV
    __m128i s = crypt.runaes_128bit(nxt_iv);
    s = _mm_xor_si128(s, iv);
    iv = nxt_iv;
    _mm_storeu_si128((__m128i*)block, s);
  }
};

/*
CTR 计数器模式:keystream = E(counter),C = P ^ keystream。
块间密钥流相互独立(仅计数器串行递增),加密与解密结构相同。
ctrInc:对16字节计数器做小端(+1)递增。
*/
class AesCTR : public AesEncrypt
{
  void ctrInc()
  {
    u8_t ivb[16];
    _mm_storeu_si128((__m128i*)ivb, iv);
    for (int i = 15; i >= 0; i--)      // 从最低字节起 +1,遇进位继续
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
    __m128i mask = crypt.runaes_128bit(iv);   // 对当前计数器生成密钥流块
    s = _mm_xor_si128(s, mask);
    ctrInc();
    _mm_storeu_si128((__m128i*)block, s);
  }
};

/*
CFB 加密(密文反馈,CFB-128):C = P ^ E(IV_prev),IV_prev 更新为 C。
与 OFB 的区别:反馈的是密文而非密钥流。
*/
class AesCFB_Enc : public AesEncrypt
{
public:
  AesCFB_Enc(u8_t *key, const u8_t *iv) : AesEncrypt(key, iv){};
  virtual void runcry(u8_t *block) override
  {
    __m128i s = _mm_loadu_si128((const __m128i*)block);
    iv = crypt.runaes_128bit(iv);        // E(IV_prev)
    iv = _mm_xor_si128(s, iv);           // 与明文异或得到密文,同时成为新IV
    _mm_storeu_si128((__m128i*)block, iv);
  }
};

/*
CFB 解密:P = C ^ E(IV_prev)。
解密同样只调用加密器(E),结构对称。
*/
class AesCFB_Dec : public AesEncrypt
{
public:
  AesCFB_Dec(u8_t *key, const u8_t *iv) : AesEncrypt(key, iv){};
  virtual void runcry(u8_t *block) override
  {
    __m128i nxt_iv = _mm_loadu_si128((const __m128i*)block); // 本块密文
    iv = crypt.runaes_128bit(iv);
    __m128i s = _mm_xor_si128(nxt_iv, iv);
    iv=nxt_iv;
    _mm_storeu_si128((__m128i*)block, s);
  }
};

/*
OFB 输出反馈模式:keystream = E(keystream_prev),C = P ^ keystream。
反馈的是密钥流而非密文,加密/解密结构完全相同。
*/
class AesOFB : public AesEncrypt
{
public:
  AesOFB(u8_t *key, const u8_t *iv) : AesEncrypt(key, iv){};
  virtual void runcry(u8_t *block) override
  {
    __m128i s = _mm_loadu_si128((const __m128i*)block);
    iv = crypt.runaes_128bit(iv);        // 密钥流迭代
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