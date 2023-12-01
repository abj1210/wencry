#ifndef MUL
#define MUL

#include <stdio.h>

void multienc_master(FILE *fp, FILE *out, keyhandle *key,
                     const int threads_num);
void multidec_master(FILE *fp, FILE *out, keyhandle *key, int tailin,
                     const int threads_num);

#endif