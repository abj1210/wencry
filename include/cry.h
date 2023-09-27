#ifndef CRY
#define CRY

#include <stdio.h>

void enc(FILE *fp, FILE *out, unsigned char *key);
int dec(FILE *fp, FILE *out, unsigned char *key);
unsigned char *gen_key();
unsigned char *read_key(char *s);
int cmphash(unsigned char *h1, unsigned char *h2);

void init();

#endif