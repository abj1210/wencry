#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/aes.h"
#include "../include/util.h"

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
  for (int i = 1; i < 11; i++)
    keyg[i] = genkey(keyg[i - 1], i);
}

void addroundkey(struct state *w, struct state *key) {
  for (int i = 0; i < 4; ++i) {
    unsigned int *p = (unsigned int *)w->s[i];
    *p ^= *((unsigned int *)key->s[i]);
  }
}

void subbytes(struct state *w) {
  for (int i = 0; i < 4; ++i) {
    unsigned char t0 = w->s[i][0], t1 = w->s[i][1], t2 = w->s[i][2],
                  t3 = w->s[i][3];
    *((unsigned int *)w->s[i]) = ((unsigned int)sub_bytes(t0)) |
                                 ((unsigned int)sub_bytes(t1) << 8) |
                                 ((unsigned int)sub_bytes(t2) << 16) |
                                 ((unsigned int)sub_bytes(t3) << 24);
  }
}

void rowshift(struct state *w) {
  for (int i = 0; i < 4; ++i) {
    unsigned int *p = (unsigned int *)w->s[i];
    *p = rrot(*p, i << 3);
  }
}

void columnmix(struct state *w) {
  unsigned char *p = ((unsigned char *)(w->s)), *pe = p + 0x4;
  while (p != pe) {
    unsigned char b0 = *p, b1 = *(p + 0x4), b2 = *(p + 0x8), b3 = *(p + 0xc);
    unsigned short GIline(0x02, 0x03, 0x01, 0x01);
    (*p) = GMline;

    GIline(0x01, 0x02, 0x03, 0x01);
    (*(p + 0x4)) = GMline;

    GIline(0x01, 0x01, 0x02, 0x03);
    (*(p + 0x8)) = GMline;

    GIline(0x03, 0x01, 0x01, 0x02);
    (*(p + 0xc)) = GMline;

    p++;
  }
}

void commonround(struct state *data, int round) {
  addroundkey(data, &keyg[round]);
  subbytes(data);
  rowshift(data);
  columnmix(data);
}

void lastround(struct state *data) {
  addroundkey(data, &keyg[9]);
  subbytes(data);
  rowshift(data);
  addroundkey(data, &keyg[10]);
}

void runaes_128bit(unsigned char *s) {
  struct state *data = (struct state *)s;
  for (int i = 0; i < 9; ++i)
    commonround(data, i);
  lastround(data);
}