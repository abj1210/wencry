#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/aes.h"

struct state genkey(struct state last_key, int round) {
  struct state now_key;
  for (int j = 0; j < 4; j++) {
    for (int i = 0; i < 4; i++) {
      if (j == 0) {
        if (i == 0) {
          now_key.s[i][j] =
              (sub_bytes(last_key.s[1][3])) ^ RC[round] ^ last_key.s[i][j];
        } else {
          now_key.s[i][j] =
              (sub_bytes(last_key.s[(i + 1) & 0x3][3])) ^ last_key.s[i][j];
        }
      } else {
        now_key.s[i][j] = now_key.s[i][j - 1] ^ last_key.s[i][j];
      }
    }
  }
  return now_key;
}

void initgen(unsigned char *init_key) {
  for (int j = 0; j < 4; j++) {
    for (int i = 0; i < 4; i++) {
      keyg[0].s[i][j] = init_key[(j << 2) | (i & 0x3)];
    }
  }
  for (int i = 1; i < 11; i++) keyg[i] = genkey(keyg[i - 1], i);
}

struct state *addroundkey(struct state *w, struct state *key) {
  for (int i = 0; i < 4; ++i) {
    *((unsigned int *)w->s[i]) ^= *((unsigned int *)key->s[i]);
  }
  return w;
}

struct state *subbytes(struct state *w) {
  for (int j = 0; j < 4; ++j) {
    for (int i = 0; i < 4; ++i) {
      unsigned char t = w->s[i][j];
      w->s[i][j] = sub_bytes(t);
    }
  }
  return w;
}

struct state *rowshift(struct state *w) {
  for (int i = 0; i < 4; ++i) {
    *((unsigned int *)w->s[i]) = rrot(*((unsigned int *)w->s[i]), i << 3);
  }
  return w;
}

struct state *columnmix(struct state *w) {
  for (int j = 0; j < 4; ++j) {
    unsigned char b0 = w->s[0][j], b1 = w->s[1][j], b2 = w->s[2][j],
                  b3 = w->s[3][j];
    w->s[0][j] =
        GMul(0x02, b0) ^ GMul(0x03, b1) ^ GMul(0x01, b2) ^ GMul(0x01, b3);
    w->s[1][j] =
        GMul(0x01, b0) ^ GMul(0x02, b1) ^ GMul(0x03, b2) ^ GMul(0x01, b3);
    w->s[2][j] =
        GMul(0x01, b0) ^ GMul(0x01, b1) ^ GMul(0x02, b2) ^ GMul(0x03, b3);
    w->s[3][j] =
        GMul(0x03, b0) ^ GMul(0x01, b1) ^ GMul(0x01, b2) ^ GMul(0x02, b3);
  }
  return w;
}

struct state *commonround(struct state *data, int round) {
  addroundkey(data, &keyg[round]);
  subbytes(data);
  rowshift(data);
  columnmix(data);

  return data;
}

struct state *lastround(struct state *data) {
  addroundkey(data, &keyg[9]);
  subbytes(data);
  rowshift(data);
  addroundkey(data, &keyg[10]);

  return data;
}

unsigned char *runaes_128bit(unsigned char *s, unsigned char *out) {
  struct state data;
  int k = 0;
  for (int j = 0; j < 4; ++j) {
    for (int i = 0; i < 4; ++i) {
      data.s[i][j] = s[k++];
    }
  }

  for (int i = 0; i < 9; ++i) commonround(&data, i);
  lastround(&data);
  k = 0;
  for (int j = 0; j < 4; ++j) {
    for (int i = 0; i < 4; ++i) {
      out[k++] = data.s[i][j];
    }
  }

  return out;
}