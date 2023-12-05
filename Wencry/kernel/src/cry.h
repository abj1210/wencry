#ifndef CRY
#define CRY

#include <stdio.h>
#include "kutil.h"

void enc(FILE *fp, FILE *out, const u8_t *r_buf, u8_t *key);
int verify(FILE *fp, u8_t *key);
int dec(FILE *fp, FILE *out, u8_t *key);

#endif