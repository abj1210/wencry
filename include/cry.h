#ifndef CRY
#define CRY

#include "key.h"
#include "util.h"
#include <stdio.h>

void enc(FILE *fp, FILE *out, const u8_t *r_buf, keyhandle *key);
int verify(FILE *fp, keyhandle *key);
int dec(FILE *fp, FILE *out, keyhandle *key);

#endif