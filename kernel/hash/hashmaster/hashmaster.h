#ifndef HSM
#define HSM

#include "modes.h"

/*################################
  模块概述:哈希算法框架(抽象基类 + 实现 + 工厂)
  HashMaster 定义统一接口:
    - getStringHash(str, len, ...)  : 哈希内存字符串。
    - resetHash/hashBlock/hashFinal/getResult : 增量哈希(HMAC融合路径)。
  SHA1/SHA256 仅保留 SHA-NI 硬件实现(Sha1Ni/Sha256Ni),整块哈希由硬件指令完成;
  软件基类 Sha1Hash/Sha256Hash 只保留状态初始化、末尾块填充与摘要输出等公共逻辑。
  MD5 无 SHA-NI 对应物,由软件 Md5Hash 实现。
  工厂 HashFactory 按 htype 返回对应实例。
  长度字段:各实现按块大小64、末尾填充为 0x80+长度(位),与标准一致。
################################*/

typedef unsigned char u8_t;
typedef unsigned int u32_t;
typedef unsigned long long u64_t;
/* lrot:将x循环左移i位(MD5 软件实现使用) */
#define lrot(x, i) (((x) << (i)) | ((x) >> (32 - (i))))
/*
HashMaster:哈希算法抽象基类
统一接口:
  - getStringHash(str,len,out)          : 哈希内存字符串。
  - resetHash/hashBlock/hashFinal/getResult : 增量哈希(HMAC融合路径)。
派生类实现纯虚的 getHash(整块/末块)/reset/computeResult 轮函数。
*/
class HashMaster
{
protected:
  /*
  totalsize:累计已处理消息的总长度(位)
  addTotalLength 逐块累加,末尾块填充时写入64位长度字段
  */
  u64_t totalsize;
  /*
  addTotalLength:累加总长度(以位计)
  len:本块字节数
  */
  void addTotalLength(u32_t len) { totalsize += ((u64_t)len << 3); };

  /* getHash:处理64字节整块 */
  virtual void getHash(const u8_t *input) = 0;
  /* getHash:处理末尾块(含填充与长度) */
  virtual void getHash(const u8_t *input, u32_t final_loadsize) = 0;
  /* reset:重置哈希状态 */
  virtual void reset() = 0;
  /* computeResult:输出摘要 */
  virtual void computeResult(u8_t *hashout) = 0;

public:
  virtual ~HashMaster() {};
  /* getHashLength:返回摘要字节长度 */
  virtual u8_t getHashLength() = 0;
  /* getBlockLength:返回块字节长度(64) */
  virtual u8_t getBlockLength() = 0;
  /*
  getStringHash:返回字符串哈希
  string:字符串指针
  length:长度
  hashres:结果哈希地址
  */
  void getStringHash(const u8_t *string, u32_t length, u8_t *hashres){
    reset();
    u32_t nnow = length;
    for (; nnow >= 64; nnow -= 64)
      getHash(string + (length - nnow));
    getHash(string + (length - nnow), nnow);
    computeResult(hashres);
  };
  /* blockFast_t:处理单个 64 字节整块的函数指针类型(热路径消除虚调用) */
  typedef void (*blockFast_t)(HashMaster *self, const u8_t *input);
  /* getBlockFast:返回本哈希器的整块处理函数 */
  virtual blockFast_t getBlockFast() const = 0;
  /*
  增量哈希接口(供HMAC融合等场景使用)
  resetHash:重置哈希状态
  hashBlock:喂入64字节整块(累积)
  hashFinal:喂入末尾块(含填充与长度)
  getResult:输出摘要
  */
  void resetHash() { reset(); };
  void hashBlock(const u8_t *input) { getHash(input); };
  void hashFinal(const u8_t *input, u32_t final_loadsize) { getHash(input, final_loadsize); };
  void getResult(u8_t *hashout) { computeResult(hashout); };
};

/*
Sha1Hash:SHA1 基类(整块哈希由子类 Sha1Ni 用 SHA-NI 实现,本类不可单独实例化)
h[5]:状态寄存器(初始常量 0x67452301...)
仅保留末尾块填充与摘要输出等公共逻辑。
*/
class Sha1Hash : public HashMaster
{
protected:
  u32_t h[5];
  using HashMaster::getHash;
  void getHash(const u8_t *input, u32_t final_loadsize);
  void init()
  {
    h[0] = 0x67452301, h[1] = 0xEFCDAB89, h[2] = 0x98BADCFE, h[3] = 0x10325476,
    h[4] = 0xC3D2E1F0;
    totalsize = 0;
  };
  void reset() { init(); };
  void computeResult(u8_t *hashout);

public:
  Sha1Hash() { init(); };
  virtual u8_t getHashLength() { return 20; };
  virtual u8_t getBlockLength() { return 64; };
};

/*
Md5Hash:MD5 软件实现
h[4]:状态寄存器
s/x:输入块(64字节/16字共用)
*/
class Md5Hash : public HashMaster
{
  u32_t h[4];
  union
  {
    u8_t s[64];
    u32_t x[16];
  };
  /* getHash:处理64字节整块(4轮64步主循环) */
  void getHash(const u8_t *input);
  /* getHash:处理末尾块(填充 + 小端长度字段) */
  void getHash(const u8_t *input, u32_t final_loadsize);
  /* blockFast:热路径整块处理(消除每块一次虚调用) */
  static void blockFast(HashMaster *self, const u8_t *input);
  void init()
  {
    h[0] = 0x67452301, h[1] = 0xEFCDAB89, h[2] = 0x98BADCFE, h[3] = 0x10325476;
    totalsize = 0;
  };
  void reset() { init(); };
  /* computeResult:输出16字节MD5摘要(小端展开) */
  void computeResult(u8_t *hashout);

public:
  Md5Hash() { init(); };
  virtual u8_t getHashLength() { return 16; };
  virtual u8_t getBlockLength() { return 64; };
  /* getBlockFast:返回整块热路径函数指针 */
  HashMaster::blockFast_t getBlockFast() const override { return &Md5Hash::blockFast; };
};

/*
Sha256Hash:SHA256 基类(整块哈希由子类 Sha256Ni 用 SHA-NI 实现,本类不可单独实例化)
h[8]:状态寄存器(初始常量 0x6a09e667...)
仅保留末尾块填充与摘要输出等公共逻辑。
*/
class Sha256Hash : public HashMaster
{
protected:
  u32_t h[8];
  using HashMaster::getHash;
  void getHash(const u8_t *input, u32_t final_loadsize);
  void init()
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
  void reset() { init(); };
  void computeResult(u8_t *hashout);

public:
  Sha256Hash() { init(); };
  virtual u8_t getHashLength() { return 32; };
  virtual u8_t getBlockLength() { return 64; };
};
#endif
