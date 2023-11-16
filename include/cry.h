#ifndef CRY
#define CRY

#include <stdio.h>

void enc(FILE *fp, FILE *out, unsigned char *key);
int dec(FILE *fp, FILE *out, unsigned char *key);
unsigned char *gen_key();
void init();

#endif