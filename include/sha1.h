#ifndef SHA1
#define SHA1

#include <stdio.h>

unsigned char *getSha1File(FILE *fp);
unsigned char *getSha1String(unsigned char *s, unsigned int n);

#endif