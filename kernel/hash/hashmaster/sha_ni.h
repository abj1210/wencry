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
仅重写64字节整块哈希,末尾块/填充/长度/输出继承自sha1hash
*/
class sha1ni : public sha1hash
{
  /* block_fast:热路径整块处理(消除每块一次虚调用) */
  static void block_fast(Hashmaster *self, const u8_t *input);
  /* getHash:用 SHA1-NI 指令处理一个64字节整块 */
  void getHash(const u8_t *input) override;
public:
  /* get_block_fast:返回整块热路径函数指针 */
  Hashmaster::block_fast_t get_block_fast() const override { return &sha1ni::block_fast; };
};

/*
SHA-NI硬件加速的SHA256哈希类
仅重写64字节整块哈希,末尾块/填充/长度/输出继承自sha256hash
*/
class sha256ni : public sha256hash
{
  /* block_fast:热路径整块处理(消除每块一次虚调用) */
  static void block_fast(Hashmaster *self, const u8_t *input);
  /* getHash:用 SHA256-NI 指令处理一个64字节整块 */
  void getHash(const u8_t *input) override;
public:
  /* get_block_fast:返回整块热路径函数指针 */
  Hashmaster::block_fast_t get_block_fast() const override { return &sha256ni::block_fast; };
};

#endif
