#include "../include/util.h"

#include <stdlib.h>
#include <string.h>
/*
read_buffer:从缓冲区读取16B数据
fp:缓冲区加载的文件指针
block:读取数据的地址
ibuf:输入缓冲区的指针
return:读取的字节数
*/
unsigned int read_buffer(FILE *fp, unsigned char *block, struct buffer *ibuf) {
  unsigned int res = 0;
  if (ibuf->now == BUF_SZ || ibuf->load == 0) {
    unsigned int sum = fread(ibuf->b, 1, BUF_SZ << 4, fp);
    ibuf->tail = sum & 0xf;
    ibuf->total = sum >> 4;
    ibuf->now = 0;
    ibuf->load = 1;
  }

  if (ibuf->now == ibuf->total) {
    memcpy(block, ibuf->b[ibuf->now], ibuf->tail);
    res = ibuf->tail;
    ibuf->tail = 0;
  } else {
    memcpy(block, ibuf->b[ibuf->now], 16);
    res = 16;
    ibuf->now++;
  }
  return res;
}
/*
bufferover:缓冲区和文件是否读取完毕
ibuf:输入缓冲区的指针
return:若为0则未读取完毕,否则已读取完毕
*/
unsigned int bufferover(struct buffer *ibuf) {
  return (ibuf->now == ibuf->total) && (ibuf->total != BUF_SZ) &&
         (ibuf->tail == 0);
}
/*
write_buffer:向缓冲区写入16B数据
fp:缓冲区存储的文件指针
block:写入数据的地址
obuf:输出缓冲区的指针
*/
void write_buffer(FILE *fp, unsigned char *block, struct buffer *obuf) {
  memcpy(obuf->b[obuf->total], block, 16);
  obuf->total++;
  if (obuf->total == BUF_SZ) {
    fwrite(obuf->b, 1, BUF_SZ << 4, fp);
    obuf->total = 0;
  }
}
/*
final_write:将缓冲区内容保存到文件并关闭缓冲区
fp:缓冲区存储的文件指针
obuf:输出缓冲区的指针
*/
void final_write(FILE *fp, struct buffer *obuf) {
  fwrite(obuf->b, 1, obuf->total << 4, fp);
}
/*
read_buffer:从缓冲区读取64B数据
fp:缓冲区加载的文件指针
block:读取数据的地址
ibuf64:输入缓冲区的指针
return:读取的字节数
*/
unsigned int read_buffer64(FILE *fp, unsigned char *block,
                           struct buffer64 *ibuf64) {
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
/*
load_buffer:从文件加载数据到缓冲区
fp:缓冲区加载的文件指针
ibuf:输入缓冲区的指针
return:加载的字节数
*/
unsigned int load_buffer(FILE *fp, struct buffer *ibuf) {
  unsigned int sum = fread(ibuf->b, 1, BUF_SZ << 4, fp);
  ibuf->tail = sum & 0xf;
  ibuf->total = sum >> 4;
  return sum;
}
/*
wread_buffer:从缓冲区指定单元读取16B数据
idx:缓冲区单元索引
block:读取数据的地址
ibuf:输入缓冲区的指针
return:读取的字节数,若失败返回-1
*/
int wread_buffer(unsigned int idx, unsigned char *block, struct buffer *ibuf) {
  int res;
  if (idx == ibuf->total) {
    if (ibuf->tail != 0)
      memcpy(block, ibuf->b[idx], ibuf->tail);
    if (ibuf->total != BUF_SZ)
      res = ibuf->tail;
    else
      res = -1;
    ibuf->now = idx;
    ibuf->tail = 0;
  } else if (idx < ibuf->total) {
    memcpy(block, ibuf->b[idx], 16);
    res = 16;
    ibuf->now = idx + 1;
  } else
    res = -1;
  return res;
}
/*
store_buffer:将缓冲区数据保存到文件中
fp:缓冲区保存的文件指针
obuf:输出缓冲区的指针
*/
void store_buffer(FILE *fp, struct buffer *obuf) {
  fwrite(obuf->b, 1, BUF_SZ << 4, fp);
  obuf->total = 0;
}
/*
wread_buffer:从缓冲区指定单元写入16B数据
idx:缓冲区单元索引
block:写入数据的地址
obuf:输出缓冲区的指针
*/
void wwrite_buffer(unsigned int idx, unsigned char *block,
                   struct buffer *obuf) {
  memcpy(obuf->b[idx], block, 16);
  obuf->total = idx + 1 > obuf->total ? idx + 1 : obuf->total;
}