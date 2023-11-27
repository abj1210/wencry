#ifndef SHA1
#define SHA1

#include <stdio.h>

unsigned char *getsha1f(FILE *fp);
unsigned char *getsha1s(unsigned char *s, unsigned int n);

#endif