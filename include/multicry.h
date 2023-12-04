#ifndef MUL
#define MUL

#include "multi_buffergroup.h"
#include "util.h"
void multienc_master(keyhandle *key, buffergroup *buf, const u8_t *r_hash,
                     u8_t &tail);
void multidec_master(keyhandle *key, buffergroup *buf, const u8_t *r_hash,
                     const u8_t tail);

#endif