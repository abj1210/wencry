#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/aes.h"
#include "../include/util.h"

void resubbytes(struct state *w) {
  for (int j = 0; j < 4; ++j) {
    for (int i = 0; i < 4; ++i) {
      unsigned char t = w->s[i][j];
      w->s[i][j] = r_sub_bytes(t);
    }
  }
}

void rerowshift(struct state *w) {
  for (int i = 0; i < 4; ++i) {
    *((unsigned int *)w->s[i]) = lrot(*((unsigned int *)w->s[i]), i << 3);
  }
}

void recolumnmix(struct state *w) {
  for (int j = 0; j < 4; ++j) {
    unsigned char b0 = w->s[0][j], b1 = w->s[1][j], b2 = w->s[2][j],
                  b3 = w->s[3][j];
    w->s[0][j] =
        GMul(0x0e, b0) ^ GMul(0x0b, b1) ^ GMul(0x0d, b2) ^ GMul(0x09, b3);
    w->s[1][j] =
        GMul(0x09, b0) ^ GMul(0x0e, b1) ^ GMul(0x0b, b2) ^ GMul(0x0d, b3);
    w->s[2][j] =
        GMul(0x0d, b0) ^ GMul(0x09, b1) ^ GMul(0x0e, b2) ^ GMul(0x0b, b3);
    w->s[3][j] =
        GMul(0x0b, b0) ^ GMul(0x0d, b1) ^ GMul(0x09, b2) ^ GMul(0x0e, b3);
  }
}

void commondec(struct state *data, int round) {
  recolumnmix(data);
  rerowshift(data);
  resubbytes(data);
  addroundkey(data, &keyg[round]);
}

void firstdec(struct state *data) {
  addroundkey(data, &keyg[10]);
  rerowshift(data);
  resubbytes(data);
  addroundkey(data, &keyg[9]);
}

void decaes_128bit(unsigned char *s, unsigned char *out) {
  struct state data;
  memcpy(data.s, s, 16);
  firstdec(&data);
  for (int i = 8; i >= 0; --i)
    commondec(&data, i);
  memcpy(out, data.s, 16);
}