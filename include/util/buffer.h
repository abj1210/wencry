#ifndef BUF
#define BUF

#include <stdio.h>
//用于aes的16B单元缓冲区单元数量
#define BUF_SZ 0x100000
/*
buffer:用于aes的16B单元缓冲区
b:缓冲区数组
total:缓冲区被填满的单元数量
now:将要被读写的单元索引
tail:未被填满的单元中数据的长度
load:是否被装载
*/
struct buffer {
  unsigned char b[BUF_SZ][0x10];
  unsigned int total;
  unsigned int now;
  unsigned char tail;
  unsigned char load;
};
//用于hash的64B单元缓冲区单元数量
#define HBUF_SZ 0x40000
/*
buffer64:用于hash的64B单元缓冲区
b:缓冲区数组
total:缓冲区被填满的单元数量
now:将要被读写的单元索引
tail:未被填满的单元中数据的长度
load:是否被装载
*/
struct buffer64 {
  unsigned char b[HBUF_SZ][0x40];
  unsigned int total;
  unsigned int now;
  unsigned char tail;
  unsigned char load;
};

unsigned int bufferover(struct buffer *ibuf);
void final_write(FILE *fp, struct buffer *obuf);
unsigned int read_buffer64(FILE *fp, unsigned char *block,
                           struct buffer64 *ibuf64);

unsigned int load_buffer(FILE *fp, struct buffer *ibuf);
int wread_buffer(unsigned int idx, unsigned char *block, struct buffer *ibuf);
void store_buffer(FILE *fp, struct buffer *obuf);
void wwrite_buffer(unsigned int idx, unsigned char *block, struct buffer *obuf);

#endif