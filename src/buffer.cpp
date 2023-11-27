#include "util.h"

#include <stdio.h>
#include <string.h>
struct iobuffer buf;
/*
load_files:设定输入输出文件并初始化缓冲区
buf:缓冲区指针
fin:输入文件地址
fout:输出文件地址
*/
bool load_files(struct iobuffer *buf, FILE *fin, FILE *fout) {
  buf->fin = fin;
  buf->fout = fout;
  unsigned int sum = fread(buf->b, 1, BUF_SZ << 4, fin);
  buf->tail = sum & 0xf;
  buf->total = sum >> 4;
  buf->now = 0;
  return sum != 0;
}
/*
get_entry:获取当前缓冲区单元表项
buf:缓冲区的指针
return:返回的表项地址
*/
unsigned char *get_entry(struct iobuffer *buf) {
  if ((buf->now < buf->total) ||
      ((buf->now == buf->total) && (buf->tail != 0))) {
    return buf->b[buf->now++];
  } else
    return NULL;
}
/*
update_buffer:保存缓冲区数据并更新缓冲区
buf:缓冲区的指针
*/
void update_buffer(struct iobuffer *buf) {
  fwrite(buf->b, 1, BUF_SZ << 4, buf->fout);
  unsigned int sum = fread(buf->b, 1, BUF_SZ << 4, buf->fin);
  buf->tail = sum & 0xf;
  buf->total = sum >> 4;
  buf->now = 0;
}
/*
bufferover:缓冲区和文件是否读取完毕
buf:缓冲区指针
return:若为0则未读取完毕,否则已读取完毕
*/
bool buffer_over(struct iobuffer *buf) {
  return (buf->now >= buf->total) && (buf->total != BUF_SZ);
}
/*
final_write:将缓冲区内容保存到文件并关闭缓冲区
buf:输出缓冲区的指针
tail:最后一表项中要保存的字节数
return:最后一表项装载的字节数
*/
unsigned int final_write(struct iobuffer *buf, int tail) {
  fwrite(buf->b, 1, ((buf->now - 1) << 4) + tail, buf->fout);
  return buf->tail == 0 ? 16 : buf->tail;
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