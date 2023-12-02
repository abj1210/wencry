#ifndef SHA1
#define SHA1

#include "util.h"
#include <stdio.h>

void getSha1File(FILE *fp, u8_t *hashout);
void getSha1String(u8_t *s, u32_t n, u8_t *hashout);

#endif