#ifndef TUL
#define TUL

#include <stdio.h>
FILE *genfile(const char *str);
void gethex(const char *str, unsigned char *out);
bool cmpstr(const unsigned char *s1, const unsigned char *s2, int n);

#endif