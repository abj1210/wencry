#ifndef MUL
#define MUL

#include <stdio.h>

void multienc_master(FILE *fp, FILE *out, int threads_num);
void multidec_master(FILE *fp, FILE *out, int tailin, int threads_num);

#endif