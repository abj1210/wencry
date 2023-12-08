#ifndef CRY
#define CRY

#include "multicry.h"
#include "sha1.h"
#include <stdio.h>
typedef unsigned char u8_t;
typedef unsigned long long u64_t;
//魔数
constexpr auto Magic_Num = 0xA5C3A500C3A5C3;
void enc(FILE *fp, FILE *out, const u8_t *r_buf, u8_t *key);
int verify(FILE *fp, u8_t *key);
int dec(FILE *fp, FILE *out, u8_t *key);

#endif