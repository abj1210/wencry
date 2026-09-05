#ifndef SHA_NI
#define SHA_NI

#include "hashmaster.h"

#ifdef _MSC_VER
#include <intrin.h>
#else
#include <wmmintrin.h>
#include <immintrin.h>
#endif

/*
SHA-NI硬件加速的SHA1哈希类
仅重写64字节整块哈希,末尾块/填充/长度/输出继承自Sha1Hash
*/
class Sha1Ni : public Sha1Hash
{
  /* blockFast:热路径整块处理(消除每块一次虚调用) */
  static void blockFast(HashMaster *self, const u8_t *input);
  /* getHash:用 SHA1-NI 指令处理一个64字节整块 */
  void getHash(const u8_t *input) override;
public:
  /* getBlockFast:返回整块热路径函数指针 */
  HashMaster::blockFast_t getBlockFast() const override { return &Sha1Ni::blockFast; };
};

/*
SHA-NI硬件加速的SHA256哈希类
仅重写64字节整块哈希,末尾块/填充/长度/输出继承自Sha256Hash
*/
class Sha256Ni : public Sha256Hash
{
  /* blockFast:热路径整块处理(消除每块一次虚调用) */
  static void blockFast(HashMaster *self, const u8_t *input);
  /* getHash:用 SHA256-NI 指令处理一个64字节整块 */
  void getHash(const u8_t *input) override;
public:
  /* getBlockFast:返回整块热路径函数指针 */
  HashMaster::blockFast_t getBlockFast() const override { return &Sha256Ni::blockFast; };
};

#endif
