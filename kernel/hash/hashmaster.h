#ifndef HSM
#define HSM

#include "modes.h"
#include <string>
#include <map>

/*################################
  模块概述:哈希算法框架(抽象基类 + 实现 + 工厂)
  Hashmaster 定义统一接口:
    - getStringHash(str, len, ...)  : 哈希内存字符串。
    - reset_hash/hash_block/hash_final/get_result : 增量哈希(HMAC融合路径)。
  SHA1/SHA256 仅保留 SHA-NI 硬件实现(sha1ni/sha256ni),整块哈希由硬件指令完成;
  软件基类 sha1hash/sha256hash 只保留状态初始化、末尾块填充与摘要输出等公共逻辑。
  MD5 无 SHA-NI 对应物,由软件 md5hash 实现。
  工厂 HashFactory 按 htype 返回对应实例。
  长度字段:各实现按块大小64、末尾填充为 0x80+长度(位),与标准一致。
################################*/

typedef unsigned char u8_t;
typedef unsigned int u32_t;
typedef unsigned long long u64_t;
/* lrot:将x循环左移i位(MD5 软件实现使用) */
#define lrot(x, i) (((x) << (i)) | ((x) >> (32 - (i))))
/*
Hashmaster:哈希算法抽象基类
统一接口:
  - getStringHash(str,len,out)          : 哈希内存字符串。
  - reset_hash/hash_block/hash_final/get_result : 增量哈希(HMAC融合路径)。
派生类实现纯虚的 getHash(整块/末块)/reset/getres 轮函数。
*/
class Hashmaster
{
protected:
  /*
  totalsize:累计已处理消息的总长度(位)
  addtotal 逐块累加,末尾块填充时写入64位长度字段
  */
  u32_t totalsize;
  /*
  addtotal:累加总长度(以位计)
  len:本块字节数
  */
  void addtotal(u32_t len) { totalsize += (len << 3); };

  /* getHash:处理64字节整块 */
  virtual void getHash(const u8_t *input) = 0;
  /* getHash:处理末尾块(含填充与长度) */
  virtual void getHash(const u8_t *input, u32_t final_loadsize) = 0;
  /* reset:重置哈希状态 */
  virtual void reset() = 0;
  /* getres:输出摘要 */
  virtual void getres(u8_t *hashout) = 0;

public:
  virtual ~Hashmaster() {};
  /* gethlen:返回摘要字节长度 */
  virtual u8_t gethlen() = 0;
  /* getblen:返回块字节长度(64) */
  virtual u8_t getblen() = 0;
  void getStringHash(const u8_t *string, u32_t length, u8_t *hashres);
  /*
  增量哈希接口(供HMAC融合等场景使用)
  reset_hash:重置哈希状态
  hash_block:喂入64字节整块(累积)
  hash_final:喂入末尾块(含填充与长度)
  get_result:输出摘要
  */
  void reset_hash() { reset(); };
  void hash_block(const u8_t *input) { getHash(input); };
  void hash_final(const u8_t *input, u32_t final_loadsize) { getHash(input, final_loadsize); };
  void get_result(u8_t *hashout) { getres(hashout); };
};

/*
sha1hash:SHA1 基类(整块哈希由子类 sha1ni 用 SHA-NI 实现,本类不可单独实例化)
h[5]:状态寄存器(初始常量 0x67452301...)
仅保留末尾块填充与摘要输出等公共逻辑。
*/
class sha1hash : public Hashmaster
{
protected:
  u32_t h[5];
  using Hashmaster::getHash;
  void getHash(const u8_t *input, u32_t final_loadsize);
  void reset()
  {
    h[0] = 0x67452301, h[1] = 0xEFCDAB89, h[2] = 0x98BADCFE, h[3] = 0x10325476,
    h[4] = 0xC3D2E1F0;
    totalsize = 0;
  };
  void getres(u8_t *hashout);

public:
  sha1hash() { reset(); };
  virtual u8_t gethlen() { return 20; };
  virtual u8_t getblen() { return 64; };
};

/*
md5hash:MD5 软件实现
h[4]:状态寄存器
s/x:输入块(64字节/16字共用)
*/
class md5hash : public Hashmaster
{
  u32_t h[4];
  union
  {
    u8_t s[64];
    u32_t x[16];
  };
  void getHash(const u8_t *input);
  void getHash(const u8_t *input, u32_t final_loadsize);
  void reset()
  {
    h[0] = 0x67452301, h[1] = 0xEFCDAB89, h[2] = 0x98BADCFE, h[3] = 0x10325476;
    totalsize = 0;
  };
  void getres(u8_t *hashout);

public:
  md5hash() { reset(); };
  virtual u8_t gethlen() { return 16; };
  virtual u8_t getblen() { return 64; };
};

/*
sha256hash:SHA256 基类(整块哈希由子类 sha256ni 用 SHA-NI 实现,本类不可单独实例化)
h[8]:状态寄存器(初始常量 0x6a09e667...)
仅保留末尾块填充与摘要输出等公共逻辑。
*/
class sha256hash : public Hashmaster
{
protected:
  u32_t h[8];
  using Hashmaster::getHash;
  void getHash(const u8_t *input, u32_t final_loadsize);
  void reset()
  {
    h[0] = 0x6a09e667;
    h[1] = 0xbb67ae85;
    h[2] = 0x3c6ef372;
    h[3] = 0xa54ff53a;
    h[4] = 0x510e527f;
    h[5] = 0x9b05688c;
    h[6] = 0x1f83d9ab;
    h[7] = 0x5be0cd19;
    totalsize = 0;
  };
  void getres(u8_t *hashout);

public:
  sha256hash() { reset(); };
  virtual u8_t gethlen() { return 32; };
  virtual u8_t getblen() { return 64; };
};
/*
哈希函数工厂类(类型列表单源见 valhelper/modes.h 的 HashType 枚举)
*/
class HashFactory
{
public:
  /*
  getType:根据数字返回哈希类型
  type:输入的数字
  return:返回的类型(非法返回 HT_COUNT 哨兵)
  */
  static HashType getType(u8_t type);
  /*
  getHasher:根据哈希类型返回相应的算法
  type:哈希类型
  return:返回的哈希类
  */
  Hashmaster *getHasher(HashType type);
};
#endif