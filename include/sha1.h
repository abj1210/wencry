#ifndef SHA1
#define SHA1

#include "util.h"
#include <stdio.h>

unsigned char *getsha1f(FILE *fp);
unsigned char *getsha1s(unsigned char *s, unsigned long long n);
#endif