#ifndef IOP
#define IOP

#include <time.h>
class keyhandle;
typedef unsigned char u8_t;
void printload(const u8_t id);
u8_t printinv(const u8_t ret);
void printres(int res);
void printenc();
void printtime(clock_t totalTime, u8_t threads_num);
#endif