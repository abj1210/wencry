#ifndef AES_NI
#define AES_NI

/* 使用Intel AES-NI指令集实现AES-128(硬件加速)。
   <wmmintrin.h> 提供 _mm_aesenc/_mm_aeskeygenassist 等指令;MSVC 与 GCC/Clang 均支持。 */

#include <wmmintrin.h>
#include <emmintrin.h>

typedef unsigned char u8_t;
typedef unsigned int u32_t;
typedef unsigned long long u64_t;

/*
AesniHandle:AES-128 轮密钥基类
key[11]:扩展后的11个轮密钥(key[0]=初始密钥,key[10]=第10轮密钥)
子类 EncryAes/DecryAes 分别实现加密与解密单块变换。
*/
class AesniHandle{
protected:
    __m128i key[11];
public:
    /*
    AesniHandle:构造函数,完成AES-128密钥扩展(见 aes_ni.cpp)
    init_key:16字节初始密钥
    */
    AesniHandle(const u8_t * init_key);
    virtual __m128i runaes_128bit(__m128i w) = 0;
};
/*
EncryAes:加密变换
runaes_128bit:AddRoundKey + 9x AESENC + AESENCLAST
*/
class EncryAes : public AesniHandle
{
public:
  EncryAes(const u8_t *initkey) : AesniHandle(initkey){};
  __m128i runaes_128bit(__m128i w) override;
};
/*
DecryAes:解密变换(等价逆密码)
invkey[11]:对扩展密钥做 AESIMC(InvMixColumns) 得到的解密轮密钥
runaes_128bit:AddRoundKey(invkey[0]) + 9x AESDEC + AESDECLAST
*/
class DecryAes : public AesniHandle
{
    __m128i invkey[11];
    /* aes128_inverse_keys:生成等价逆密码的解密轮密钥(见 aes_ni.cpp) */
    void aes128_inverse_keys();
public:
  DecryAes(const u8_t *initkey) : AesniHandle(initkey){aes128_inverse_keys();};
  __m128i runaes_128bit(__m128i w) override;
};
#endif