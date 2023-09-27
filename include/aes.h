#ifndef AES
#define AES

#include "util.h"

extern const unsigned char RC[11];
extern const unsigned char s_box[256], rs_box[256];
extern const unsigned char Logtable[256], Alogtable[256];
extern struct state keyg[11];
extern struct Wthread tlist[NUM_THREADS];


struct state genkey(struct state last_key, int round);
void addroundkey(struct state *w, struct state *key);
void subbytes(struct state *w);
void rowshift(struct state *w);
void columnmix(struct state *w);
void initgen(unsigned char *init_key);

void resubbytes(struct state *w);
void rerowshift(struct state *w);
void recolumnmix(struct state *w);

void commonround(struct state *data, int round);
void lastround(struct state *data);

void commondec(struct state *data, int round);
void firstdec(struct state *data);

void runaes_128bit(unsigned char *s);
void decaes_128bit(unsigned char *s);

#endif