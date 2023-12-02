#ifndef STU
#define STU

#include "util.h"
#include <stdio.h>
typedef unsigned char u8_t;
typedef unsigned int u32_t;
typedef unsigned long long u64_t;
class keyhandle;
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
/*
vpak:参数包
fp:输入文件
out:输出文件
key:初始密钥
mode:模式(加密/解密)
*/
typedef struct {
  FILE *fp, *out;
  keyhandle *key;
  char mode;
} vpak_t;
/*
wdata:sha1生成的w数组
w:320B数据
*/
typedef struct {
  u32_t w[80];
} wdata_t;
/*
hash:sha1的hash基本单元
h:20B数据
*/
typedef struct {
  u32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
} hash_t;

#endif