#ifndef STT
#define STT
typedef unsigned char u8_t;
typedef unsigned short u16_t;
typedef unsigned int u32_t;
typedef unsigned long long u64_t;
/*
state:用于aes操作的基本单元
s:16B数据
*/
typedef struct {
  union {
    struct {
      u64_t datal, datah;
    };
    u32_t g[4];
    u8_t s[4][4];
  };
} state_t;

#endif