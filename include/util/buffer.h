#ifndef BUF
#define BUF

#include <stdio.h>
//用于aes的16B单元缓冲区单元数量
const unsigned BUF_SZ=0x100000;

//用于hash的64B单元缓冲区单元数量
const unsigned HBUF_SZ=0x40000;

/*
iobuffer:用于aes的16B单元输入输出缓冲区
b:缓冲区数组
total:缓冲区被填满的单元数量
now:将要被读写的单元索引
tail:未被填满的单元中数据的长度
fin:读取文件的地址
fout:写入文件的地址
*/
struct iobuffer {
  unsigned char b[BUF_SZ][0x10];
  unsigned int total;
  unsigned int now;
  unsigned char tail;
  FILE *fin, *fout;
};

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

unsigned int read_buffer64(FILE *fp, unsigned char *block,
                           struct buffer64 *ibuf64);

bool load_files(struct iobuffer *buf, FILE *fin, FILE *fout);
unsigned char *get_entry(struct iobuffer *buf);
void update_buffer(struct iobuffer *buf);
bool buffer_over(struct iobuffer *buf);
unsigned int final_write(struct iobuffer *buf, int tail);

#endif