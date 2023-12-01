#ifndef SHA1
#define SHA1

#include <stdio.h>

void getSha1File(FILE *fp, unsigned char *hashout);
void getSha1String(unsigned char *s, unsigned int n, unsigned char *hashout);

#endif