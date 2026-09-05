#include "aesmode.h"
#include "modes.h"

/*################################
  AES算法子类实现
  每种模式实现 AesMode::runCrypt(对单个16字节块原地加解密),
  并维护各自的 IV/计数器状态(iv 成员,线程独占)。
################################*/

/* 加密单元基类:持有 AES-NI 加密器 */
class AesEncrypt : public AesMode
{
protected:
  AesEncryptor crypt;

public:
  AesEncrypt(u8_t *key, const u8_t *iv) : AesMode(iv), crypt(key){};
};

/* 解密单元基类:持有 AES-NI 解密器 */
class AesDecrypt : public AesMode
{
protected:
  AesDecryptor crypt;

public:
  AesDecrypt(u8_t *key, const u8_t *iv) : AesMode(iv), crypt(key){};
};

/*
ECB 加密:块之间相互独立,不使用 IV。
C = E(P)            (每块独立)
*/
class AesEcbEnc : public AesEncrypt
{
public:
  AesEcbEnc(u8_t *key, const u8_t *iv) : AesEncrypt(key, iv){};
  virtual void runCrypt(u8_t *block) override {
    __m128i s = _mm_loadu_si128((const __m128i*)block);
    s = crypt.runAes128(s);
    _mm_storeu_si128((__m128i*)block, s);
  };
};

/*
ECB 解密:P = D(C)
*/
class AesEcbDec : public AesDecrypt
{
public:
  AesEcbDec(u8_t *key, const u8_t *iv) : AesDecrypt(key, iv){};
  virtual void runCrypt(u8_t *block) override {
    __m128i s = _mm_loadu_si128((const __m128i*)block);
    s = crypt.runAes128(s);
    _mm_storeu_si128((__m128i*)block, s);
   };
};

/*
CBC 加密:C = E(P ^ IV_prev),IV_prev 逐块更新为上一块密文。
块间串行依赖,属于链式模式。
*/
class AesCbcEnc : public AesEncrypt
{
public:
  AesCbcEnc(u8_t *key, const u8_t *iv) : AesEncrypt(key, iv){};
  virtual void runCrypt(u8_t *block) override
  {
    __m128i s = _mm_loadu_si128((const __m128i*)block);
    s = _mm_xor_si128(s, iv);              // 明文与上一块密文(或初始IV)异或
    iv = crypt.runAes128(s);           // 加密,结果作为下一块的IV
    _mm_storeu_si128((__m128i*)block, iv);
  }
};

/*
CBC 解密:P = D(C) ^ IV_prev。
先保存当前密文作为下一块IV,再解密并与上一块密文异或。
*/
class AesCbcDec : public AesDecrypt
{
public:
  AesCbcDec(u8_t *key, const u8_t *iv) : AesDecrypt(key, iv){};
  virtual void runCrypt(u8_t *block) override
  {
    __m128i nxt_iv = _mm_loadu_si128((const __m128i*)block); // 本块密文,稍后作为下一块IV
    __m128i s = crypt.runAes128(nxt_iv);
    s = _mm_xor_si128(s, iv);
    iv = nxt_iv;
    _mm_storeu_si128((__m128i*)block, s);
  }
};

/*
CTR 计数器模式:keystream = E(counter),C = P ^ keystream。
块间密钥流相互独立(仅计数器串行递增),加密与解密结构相同。
ctrIncrement:对16字节计数器做小端(+1)递增。
*/
class AesCtr : public AesEncrypt
{
  void ctrIncrement()
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
  AesCtr(u8_t *key, const u8_t *iv) : AesEncrypt(key, iv){};
  virtual void runCrypt(u8_t *block) override
  {
    __m128i s = _mm_loadu_si128((const __m128i*)block);
    __m128i mask = crypt.runAes128(iv);   // 对当前计数器生成密钥流块
    s = _mm_xor_si128(s, mask);
    ctrIncrement();
    _mm_storeu_si128((__m128i*)block, s);
  }
};

/*
CFB 加密(密文反馈,CFB-128):C = P ^ E(IV_prev),IV_prev 更新为 C。
与 OFB 的区别:反馈的是密文而非密钥流。
*/
class AesCfbEnc : public AesEncrypt
{
public:
  AesCfbEnc(u8_t *key, const u8_t *iv) : AesEncrypt(key, iv){};
  virtual void runCrypt(u8_t *block) override
  {
    __m128i s = _mm_loadu_si128((const __m128i*)block);
    iv = crypt.runAes128(iv);        // E(IV_prev)
    iv = _mm_xor_si128(s, iv);           // 与明文异或得到密文,同时成为新IV
    _mm_storeu_si128((__m128i*)block, iv);
  }
};

/*
CFB 解密:P = C ^ E(IV_prev)。
解密同样只调用加密器(E),结构对称。
*/
class AesCfbDec : public AesEncrypt
{
public:
  AesCfbDec(u8_t *key, const u8_t *iv) : AesEncrypt(key, iv){};
  virtual void runCrypt(u8_t *block) override
  {
    __m128i nxt_iv = _mm_loadu_si128((const __m128i*)block); // 本块密文
    iv = crypt.runAes128(iv);
    __m128i s = _mm_xor_si128(nxt_iv, iv);
    iv=nxt_iv;
    _mm_storeu_si128((__m128i*)block, s);
  }
};

/*
OFB 输出反馈模式:keystream = E(keystream_prev),C = P ^ keystream。
反馈的是密钥流而非密文,加密/解密结构完全相同。
*/
class AesOfb : public AesEncrypt
{
public:
  AesOfb(u8_t *key, const u8_t *iv) : AesEncrypt(key, iv){};
  virtual void runCrypt(u8_t *block) override
  {
    __m128i s = _mm_loadu_si128((const __m128i*)block);
    iv = crypt.runAes128(iv);        // 密钥流迭代
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
AesMode *AesFactory::createCryMaster(bool isenc, u8_t type, const u8_t *iv)
{
  if (isenc)
  {
    switch (type)
    {
    case CM_ECB:
      return new AesEcbEnc(key, iv);
    case CM_CBC:
      return new AesCbcEnc(key, iv);
    case CM_CTR:
      return new AesCtr(key, iv);
    case CM_CFB:
      return new AesCfbEnc(key, iv);
    case CM_OFB:
      return new AesOfb(key, iv);
    default:
      return NULL;
    }
  }
  else
  {
    switch (type)
    {
    case CM_ECB:
      return new AesEcbDec(key, iv);
    case CM_CBC:
      return new AesCbcDec(key, iv);
    case CM_CTR:
      return new AesCtr(key, iv);
    case CM_CFB:
      return new AesCfbDec(key, iv);
    case CM_OFB:
      return new AesOfb(key, iv);
    default:
      return NULL;
    }
  }
}
/*
createCryMaster:按加密模式创建AES加解密器(使用工厂默认IV)
isenc:是否加密(true加密,false解密)
type:模式(0=ECB,1=CBC,2=CTR,3=CFB,4=OFB)
return:创建出的AesMode子类
*/
AesMode *AesFactory::createCryMaster(bool isenc, u8_t type)
{
  return createCryMaster(isenc, type, iv);
}