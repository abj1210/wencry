#ifndef CRY
#define CRY

#include <stdio.h>
typedef unsigned char u8_t;
//魔数
constexpr auto Magic_Num = 0xA5C3A500C3A5C3;
//线程数
constexpr auto THREADS_NUM = 4;
void enc(FILE *fp, FILE *out, const u8_t *r_buf, u8_t *key);
int verify(FILE *fp, u8_t *key);
int dec(FILE *fp, FILE *out, u8_t *key);

#endif