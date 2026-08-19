#ifndef AMD
#define AMD

//#include "aes.h"
#include "aes_ni.h"
#include <string.h>
#include <string>
#include <stdio.h>
/*
Aesmode:带模式的AES加解密单元(策略模式基类)
每个实例由某个工作线程独占,内部维护该线程独立的IV状态链:
  - 链式模式(CBC/CFB/OFB):iv在块间串行传递
  - CTR:iv为计数器,块间逐次递增
  - ECB:不使用iv
线程 i 使用由 prepare_AES 传入的 iv + 20*i(独立IV),避免多线程密钥流重用。
*/
class Aesmode
{
protected:
  __m128i iv;   // 当前迭代向量(链式状态/计数器)

public:
  explicit Aesmode(const u8_t *iv)
  {
    this->iv = _mm_loadu_si128((const __m128i *)iv);
  };
  virtual ~Aesmode() {};
  /*
  runcry:对单个16字节块执行加解密(原地)
  block:16字节块首地址
  */
  virtual void runcry(u8_t *block) = 0;
};
/*
Aes加密工厂类(工厂模式)
持有密钥与默认IV,按模式创建对应的 Aesmode 子类。
*/
class AesFactory {
  u8_t * key;         // AES-128 密钥(16字节)
  const u8_t *iv;     // 默认IV(使用3参 createCryMaster 时被显式IV覆盖)
public:
  explicit AesFactory(u8_t *key): key(key) {};
  AesFactory(u8_t *key, const u8_t * iv): key(key), iv(iv) {};
  /*
  createCryMaster:按加密模式创建AES加解密器(显式IV)
  isenc:是否加密(true加密,false解密)
  type:模式(0=ECB,1=CBC,2=CTR,3=CFB,4=OFB)
  iv:初始向量
  return:创建出的Aesmode子类
  */
  Aesmode * createCryMaster(bool isenc, u8_t type, const u8_t * iv);
  /*
  createCryMaster:按加密模式创建AES加解密器(使用工厂默认IV)
  isenc:是否加密
  type:模式(0=ECB,1=CBC,2=CTR,3=CFB,4=OFB)
  return:创建出的Aesmode子类
  */
  Aesmode * createCryMaster(bool isenc, u8_t type);
};

#endif
