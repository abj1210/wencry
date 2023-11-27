#ifndef CRY
#define CRY
#include "util.h"
void enc(FILE *fp, FILE *out, struct iobuffer &buf, unsigned char *key);
int verify(FILE *fp, unsigned char *key);
int dec(FILE *fp, FILE *out, struct iobuffer &buf, unsigned char *key);

#endif