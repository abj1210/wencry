#ifndef MUL
#define MUL

#include "multi_buffergroup.h"
#include "kutil.h"
void multienc_master(u8_t *key, buffergroup *buf, const u8_t *r_hash,
                     u8_t &tail);
void multidec_master(u8_t *key, buffergroup *buf, const u8_t *r_hash,
                     const u8_t tail);

#endif