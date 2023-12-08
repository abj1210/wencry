#ifndef RPT
#define RPT
typedef unsigned char u8_t;
#include <time.h>
u8_t printinv(const u8_t ret);
void printtime(clock_t totalTime, u8_t threads_num);
void printenc();
void printres(int res);
#endif