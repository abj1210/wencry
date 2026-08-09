#ifndef TST
#define TST

#include <stdio.h>

typedef unsigned char u8_t;

bool exec(int argc, char *argv[]);
int cmp_file(FILE *x, FILE *y);
int makeFullTest(const char *str, u8_t type = 0);
int makeBigTest(int offset, u8_t type = 0);
double makeSpeedTest(u8_t type = 0);

#endif