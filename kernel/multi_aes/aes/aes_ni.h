#ifndef AES_NI
#define AES_NI

#include <wmmintrin.h>
#include <emmintrin.h>

typedef unsigned char u8_t;
typedef unsigned short u16_t;
typedef unsigned int u32_t;
typedef unsigned long long u64_t;

class AesniHandle{
protected:
    __m128i key[11];
public:
    AesniHandle(const u8_t * init_key);
    virtual __m128i runaes_128bit(__m128i w) = 0;
};
class EncryAes : public AesniHandle
{
public:
  EncryAes(const u8_t *initkey) : AesniHandle(initkey){};
  __m128i runaes_128bit(__m128i w) override;
};
class DecryAes : public AesniHandle
{
    __m128i invkey[11];
    void aes128_inverse_keys();
public:
  DecryAes(const u8_t *initkey) : AesniHandle(initkey){aes128_inverse_keys();};
  __m128i runaes_128bit(__m128i w) override;
};
#endif