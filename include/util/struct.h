#ifndef STU
#define STU

#include <stdio.h>

struct state {
  unsigned char s[4][4];
};

struct vpak {
  FILE *fp, *out;
  unsigned char *key;
  char mode;
};

struct wdata {
  unsigned w[80];
};

struct hash {
  unsigned h[5];
};

#define BUF_SZ 0x100000

struct buffer {
  unsigned char b[BUF_SZ][0x10];
  unsigned int total;
  unsigned int now;
  unsigned char tail;
  unsigned char load;
};

#define HBUF_SZ 0x40000

struct buffer64 {
  unsigned char b[HBUF_SZ][0x40];
  unsigned int total;
  unsigned int now;
  unsigned char tail;
  unsigned char load;
};

#endif