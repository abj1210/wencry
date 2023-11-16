#ifndef AES
#define AES

#include "util.h"

extern const unsigned char RC[11];
extern const unsigned char s_box[256], rs_box[256];
extern const unsigned char Logtable[256], Alogtable[256];
extern struct state keyg[11];
extern struct buffer ibuf, obuf; //输入和输出缓冲区

void initgen(unsigned char *init_key);

void runaes_128bit(unsigned char *s);
void decaes_128bit(unsigned char *s);

#endif