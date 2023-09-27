#ifndef SHA1
#define SHA1

#include "util.h"
#include <stdio.h>

struct wdata *getwdata(unsigned char *s, struct wdata *w);
void gethash(struct hash *h, struct wdata *w);

unsigned char *getsha1f(FILE *fp);
unsigned char *getsha1s(unsigned char *s, unsigned long long n);
#endif