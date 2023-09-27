#ifndef BUF
#define BUF

#include <stdio.h>
#define BUF_SZ 0x1000000

struct buffer {
  unsigned char b[BUF_SZ][0x10];
  unsigned int total;
  unsigned int now;
  unsigned char tail;
  unsigned char load;
};

#define HBUF_SZ 0x400000

struct buffer64 {
  unsigned char b[HBUF_SZ][0x40];
  unsigned int total;
  unsigned int now;
  unsigned char tail;
  unsigned char load;
};

unsigned int read_buffer(FILE *fp, unsigned char *block, struct buffer *ibuf);
unsigned int bufferover(struct buffer *ibuf);
void write_buffer(FILE *fp, unsigned char *block, struct buffer *obuf);
void final_write(FILE *fp, struct buffer *obuf);
unsigned int read_buffer64(FILE *fp, unsigned char *block,
                           struct buffer64 *ibuf64);

unsigned int load_buffer(FILE *fp, struct buffer *ibuf);
int wread_buffer(unsigned int idx, unsigned char *block, struct buffer *ibuf);
void store_buffer(FILE *fp, struct buffer *obuf);
void wwrite_buffer(unsigned int idx, unsigned char *block, struct buffer *obuf);

#endif