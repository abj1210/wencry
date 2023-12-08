#ifndef MUL
#define MUL
#include <stdio.h>
typedef unsigned char u8_t;
//线程数
constexpr auto THREADS_NUM = 4;
void multienc_master(FILE *fp, FILE *out, u8_t *key, const u8_t *r_hash,
                     const u8_t threads_num, u8_t &tail);
void multidec_master(FILE *fp, FILE *out, u8_t *key, const u8_t *r_hash,
                     const u8_t threads_num, const u8_t tail);

#endif