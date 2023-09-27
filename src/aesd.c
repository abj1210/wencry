#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/aes.h"
#include "../include/util.h"

void resubbytes(struct state *w) {
  for (int i = 0; i < 4; ++i) {
    unsigned char t0 = w->s[i][0], t1=w->s[i][1], t2 = w->s[i][2], t3=w->s[i][3];
    *((unsigned int *)w->s[i]) = ((unsigned int)r_sub_bytes(t0))|((unsigned int)r_sub_bytes(t1)<<8)|((unsigned int)r_sub_bytes(t2)<<16)|((unsigned int)r_sub_bytes(t3)<<24);
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
    unsigned short idx0, idx1, idx2, idx3;
    idx0 = Gidx(0x0e, b0), idx1 = Gidx(0x0b, b1), idx2 = Gidx(0x0d, b2),
    idx3 = Gidx(0x09, b3);
    w->s[0][j] =
        Gmul(idx0, b0) ^ Gmul(idx1, b1) ^ Gmul(idx2, b2) ^ Gmul(idx3, b3);
    idx0 = Gidx(0x09, b0), idx1 = Gidx(0x0e, b1), idx2 = Gidx(0x0b, b2),
    idx3 = Gidx(0x0d, b3);
    w->s[1][j] =
        Gmul(idx0, b0) ^ Gmul(idx1, b1) ^ Gmul(idx2, b2) ^ Gmul(idx3, b3);
    idx0 = Gidx(0x0d, b0), idx1 = Gidx(0x09, b1), idx2 = Gidx(0x0e, b2),
    idx3 = Gidx(0x0b, b3);
    w->s[2][j] =
        Gmul(idx0, b0) ^ Gmul(idx1, b1) ^ Gmul(idx2, b2) ^ Gmul(idx3, b3);
    idx0 = Gidx(0x0b, b0), idx1 = Gidx(0x0d, b1), idx2 = Gidx(0x09, b2),
    idx3 = Gidx(0x0e, b3);
    w->s[3][j] =
        Gmul(idx0, b0) ^ Gmul(idx1, b1) ^ Gmul(idx2, b2) ^ Gmul(idx3, b3);
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

void decaes_128bit(unsigned char *s) {
  struct state *data = (struct state *)s;
  firstdec(data);
  for (int i = 8; i >= 0; --i)
    commondec(data, i);
}