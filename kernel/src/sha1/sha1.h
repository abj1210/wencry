#ifndef SHA1
#define SHA1

#include "macro.h"
#include <stdio.h>
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

void getSha1File(FILE *fp, u8_t *hashout);
void getSha1String(const u8_t *s, u32_t n, u8_t *hashout);

#endif