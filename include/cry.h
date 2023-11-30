#ifndef CRY
#define CRY

#include "key.h"
#include <stdio.h>

void enc(FILE *fp, FILE *out, keyhandle *key);
int verify(FILE *fp, keyhandle *key);
int dec(FILE *fp, FILE *out, keyhandle *key);

#endif