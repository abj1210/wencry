#ifndef MUL
#define MUL
typedef unsigned char u8_t;
#include "multi_buffergroup.h"
void multienc_master(u8_t *key, buffergroup *buf, const u8_t *r_hash, const u8_t threads_num,
                     u8_t &tail);
void multidec_master(u8_t *key, buffergroup *buf, const u8_t *r_hash, const u8_t threads_num,
                     const u8_t tail);

#endif