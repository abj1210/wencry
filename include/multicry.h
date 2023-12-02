#ifndef MUL
#define MUL

#include "multi_buffergroup.h"
#include "util.h"
void multienc_master(keyhandle *key, buffergroup *buf, u8_t &tail);
void multidec_master(keyhandle *key, buffergroup *buf, u8_t &tail);

#endif