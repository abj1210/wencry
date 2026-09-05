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
AesNiHandle:AES-128 轮密钥基类
key[11]:扩展后的11个轮密钥(key[0]=初始密钥,key[10]=第10轮密钥)
子类 AesEncryptor/AesDecryptor 分别实现加密与解密单块变换。
*/
class AesNiHandle{
protected:
    __m128i key[11];
public:
    /*
    AesNiHandle:构造函数,完成AES-128密钥扩展(见 aes_ni.cpp)
    init_key:16字节初始密钥
    */
    AesNiHandle(const u8_t * init_key);
    virtual __m128i runAes128(__m128i w) = 0;
};
/*
AesEncryptor:加密变换
runAes128:AddRoundKey + 9x AESENC + AESENCLAST
*/
class AesEncryptor : public AesNiHandle
{
public:
  AesEncryptor(const u8_t *initkey) : AesNiHandle(initkey){};
  __m128i runAes128(__m128i w) override;
};
/*
AesDecryptor:解密变换(等价逆密码)
invkey[11]:对扩展密钥做 AESIMC(InvMixColumns) 得到的解密轮密钥
runAes128:AddRoundKey(invkey[0]) + 9x AESDEC + AESDECLAST
*/
class AesDecryptor : public AesNiHandle
{
    __m128i invkey[11];
    /* aes128InverseKeys:生成等价逆密码的解密轮密钥(见 aes_ni.cpp) */
    void aes128InverseKeys();
public:
  AesDecryptor(const u8_t *initkey) : AesNiHandle(initkey){aes128InverseKeys();};
  __m128i runAes128(__m128i w) override;
};
#endif