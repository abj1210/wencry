#ifndef STU
#define STU

#include <stdio.h>
#include <pthread.h>

#include "def.h"

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

struct Wthread {
  pthread_t pts;
  int tid;
  char taskover;
};



#endif