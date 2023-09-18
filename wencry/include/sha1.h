#ifndef SHA1
#define SHA1

#include <stdio.h>

#define leftrot(x, i) (((x) << (i)) | ((x) >> (32 - i)))
#define HASH0 0x67452301
#define HASH1 0xEFCDAB89
#define HASH2 0x98BADCFE
#define HASH3 0x10325476
#define HASH4 0xC3D2E1F0

#define HBUF_SZ 0x40000

struct wdata {
  unsigned w[80];
};

struct hash {
  unsigned h[5];
};

unsigned int read_buffer64(FILE* fp, unsigned char* block);

struct wdata* getwdata(unsigned char* s, struct wdata* w);
void gethash(struct hash* h, struct wdata* w);

unsigned char* getsha1f(FILE* fp);
unsigned char* getsha1s(unsigned char* s, unsigned long long n);
#endif