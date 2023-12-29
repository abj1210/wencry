#ifndef TST
#define TST

typedef unsigned char u8_t;

int makeFullTest(const char *str, u8_t type = 0);
int makeBigTest(int offset, u8_t type = 0);
int makeSpeedTest(u8_t type = 0);

#endif