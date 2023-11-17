#ifndef CRY
#define CRY
#include "util.h"
void enc(FILE *fp, FILE *out, unsigned char *key);
int dec(FILE *fp, FILE *out, unsigned char *key);

#endif