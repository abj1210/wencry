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
  void getHash(const u8_t *input) override;
};

/*
SHA-NI硬件加速的SHA256哈希类
仅重写64字节整块哈希,末尾块/填充/长度/输出继承自sha256hash
*/
class sha256ni : public sha256hash
{
  void getHash(const u8_t *input) override;
};

#endif
