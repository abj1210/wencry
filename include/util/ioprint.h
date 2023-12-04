#ifndef IOP
#define IOP

#include <time.h>
class keyhandle;
typedef unsigned char u8_t;
void printload(const u8_t id);
u8_t printinv(const u8_t ret);
bool printterr();
void printres(u8_t res);
void printenc();
void printtime(clock_t totalTime);
void printkey(keyhandle *key);
#endif