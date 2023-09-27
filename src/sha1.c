#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/sha1.h"
#include "../include/util.h"

struct buffer64 * ibuf64=NULL;
unsigned int read_buffer64(FILE *fp, unsigned char *block) {
  if (ibuf64 == NULL) {
    ibuf64 = malloc(sizeof(struct buffer64));
    ibuf64->load = 0;
  }
  unsigned int res = 0;
  if (ibuf64->now == HBUF_SZ || ibuf64->load == 0) {
    unsigned int sum = fread(ibuf64->b, 1, HBUF_SZ << 6, fp);
    ibuf64->tail = sum & 0x3f;
    ibuf64->total = sum >> 6;
    ibuf64->now = 0;
    ibuf64->load = 1;
  }

  if (ibuf64->now == ibuf64->total) {
    memcpy(block, ibuf64->b[ibuf64->now], ibuf64->tail);
    res = ibuf64->tail;
    ibuf64->tail = 0;
  } else {
    memcpy(block, ibuf64->b[ibuf64->now], 64);
    res = 64;
    ibuf64->now++;
  }
  return res;
}

struct wdata *getwdata(unsigned char *s, struct wdata *w) {
  for (int i = 0; i < 80; i++) {
    if (i < 16)
      w->w[i] = ((unsigned)s[(i << 2) | 3]) | ((unsigned)s[(i << 2) | 2] << 8) |
                ((unsigned)s[(i << 2) | 1] << 16) | ((unsigned)s[i << 2] << 24);
    else
      w->w[i] = lrot(
          ((w->w[i - 3]) ^ (w->w[i - 8]) ^ (w->w[i - 14]) ^ (w->w[i - 16])), 1);
  }
  return w;
}

void gethash(struct hash *h, struct wdata *w) {
  struct hash temph;
  unsigned f, k, temp;
  memcpy(&temph, h, sizeof(temph));

  for (unsigned i = 0; i < 80; i++) {
    switch (i / 20) {
    case (0): {
      f = (temph.h[1] & temph.h[2]) | ((~temph.h[1]) & temph.h[3]);
      k = 0x5A827999;
      break;
    }
    case (1): {
      f = temph.h[1] ^ temph.h[2] ^ temph.h[3];
      k = 0x6ED9EBA1;
      break;
    }
    case (2): {
      f = (temph.h[1] & temph.h[2]) | (temph.h[1] & temph.h[3]) |
          (temph.h[2] & temph.h[3]);
      k = 0x8F1BBCDC;
      break;
    }
    case (3): {
      f = temph.h[1] ^ temph.h[2] ^ temph.h[3];
      k = 0xCA62C1D6;
      break;
    }
    }
    temp = lrot(temph.h[0], 5) + f + k + temph.h[4] + w->w[i];
    temph.h[4] = temph.h[3];
    temph.h[3] = temph.h[2];
    temph.h[2] = lrot(temph.h[1], 30);
    temph.h[1] = temph.h[0];
    temph.h[0] = temp;
  }

  h->h[0] += temph.h[0];
  h->h[1] += temph.h[1];
  h->h[2] += temph.h[2];
  h->h[3] += temph.h[3];
  h->h[4] += temph.h[4];
}

unsigned char *getsha1f(FILE *fp) {
  if (fp == NULL)
    return NULL;
  struct hash *h = malloc(sizeof(struct hash));
  h->h[0] = HASH0;
  h->h[1] = HASH1;
  h->h[2] = HASH2;
  h->h[3] = HASH3;
  h->h[4] = HASH4;

  unsigned char s1[64];
  int flag = 0;
  struct wdata w;
  for (unsigned long long i = 0; flag != 2; i++) {
    memset(s1, 0, sizeof(s1));
    unsigned sum = read_buffer64(fp, s1);
    if (sum != 64 && flag == 0) {
      s1[sum] = 0x80u;
      sum++;
      flag = 1;
    }
    if (sum < 56) {
      unsigned long long b = i * 512 + (sum - 1) * 8;
      for (int i = 0; i < 8; i++) {
        s1[56 + i] = ((b >> (7 - i) * 8) & 0xffu);
      }
      flag = 2;
    }
    getwdata(s1, &w);
    gethash(h, &w);
  }
  unsigned char *sha1res = malloc(20 * sizeof(unsigned char));
  for (int i = 0; i < 20; i++) {
    sha1res[i] = ((h->h[i / 4]) >> (8 * (3 - (i % 4)))) & 0x000000ffu;
  }
  free(ibuf64);
  ibuf64 = NULL;
  free(h);
  return sha1res;
}

unsigned char *getsha1s(unsigned char *s, unsigned long long n) {
  struct hash *h = malloc(sizeof(struct hash));
  h->h[0] = HASH0;
  h->h[1] = HASH1;
  h->h[2] = HASH2;
  h->h[3] = HASH3;
  h->h[4] = HASH4;

  unsigned long long b = n * 8, cnum;

  int flag = 0;

  if ((b + 8) % 512 >= 448)
    cnum = b / 512 + 2;
  else
    cnum = b / 512 + 1;

  unsigned char s1[64];
  struct wdata w;
  for (unsigned long long i = 0; i < cnum; i++) {
    memset(s1, 0, sizeof(s1));

    if ((i << 6) < n) {
      if (n - (i << 6) < 64) {
        memcpy(s1, s + (i << 6), n - (i << 6));
        s1[n - (i << 6)] = 0x80u;
        flag = 1;

      } else {
        memcpy(s1, s + (i << 6), 64);
      }
    } else if (!flag)
      s1[0] = 0x80u;
    if (i == cnum - 1) {
      for (int i = 0; i < 8; i++) {
        s1[56 + i] = ((b >> (7 - i) * 8) & 0xffu);
      }
    }
    getwdata(s1, &w);
    gethash(h, &w);
  }
  unsigned char *sha1res = malloc(20 * sizeof(unsigned char));
  for (int i = 0; i < 20; i++) {
    sha1res[i] = ((h->h[i / 4]) >> (8 * (3 - (i % 4)))) & 0x000000ffu;
  }
  free(h);
  return sha1res;
}