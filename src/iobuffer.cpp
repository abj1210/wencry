#include "util.h"

#include <stdio.h>
#include <string.h>

/*
load_files:设定输入输出文件并初始化缓冲区
fin:输入文件地址
fout:输出文件地址
return:是否成功装载数据
*/
bool iobuffer::load_files(FILE *fin, FILE *fout) {
  this->fin = fin;
  this->fout = fout;
  unsigned int sum = fread(b, 1, BUF_SZ << 4, fin);
  tail = sum & 0xf;
  total = sum >> 4;
  now = 0;
  if (sum == 0)
    this->fin = NULL;
  return sum != 0;
}
/*
get_entry:获取当前缓冲区单元表项
return:返回的表项地址
*/
unsigned char *iobuffer::get_entry() {
  if ((now < total) || ((now == total) && (tail != 0)))
    return b[now++];
  else
    return NULL;
}
/*
update_buffer:保存缓冲区数据并更新缓冲区
return:重新读入的字节数
*/
unsigned int iobuffer::update_buffer() {
  fwrite(b, 1, BUF_SZ << 4, fout);
  unsigned int sum = fread(b, 1, BUF_SZ << 4, fin);
  tail = sum & 0xf;
  total = sum >> 4;
  now = 0;
  return sum;
}
/*
bufferover:缓冲区和文件是否读取完毕
return:若为0则未读取完毕,否则已读取完毕
*/
bool iobuffer::buffer_over() { return (now >= total) && (total != BUF_SZ); }
/*
fin_empty:判断缓冲区写入文件指针是否为空
return:若为空返回真否则返回假
*/
bool iobuffer::fin_empty() { return fin == NULL; }
/*
final_write:将缓冲区内容保存到文件并关闭缓冲区
tailin:最后一表项中要保存的字节数
return:最后一表项装载的字节数
*/
unsigned int iobuffer::final_write(int tailin) {
  fwrite(b, 1, ((now - 1) << 4) + tailin, fout);
  return tail == 0 ? 16 : tail;
}
buffer64::buffer64() : now(0), load(0) {}
/*
read_buffer:从缓冲区读取64B数据
fp:缓冲区加载的文件指针
block:读取数据的地址
return:读取的字节数
*/
unsigned int buffer64::read_buffer64(FILE *fp, unsigned char *block) {
  unsigned int res = 0;
  if (now == HBUF_SZ || load == 0) {
    unsigned int sum = fread(b, 1, HBUF_SZ << 6, fp);
    tail = sum & 0x3f;
    total = sum >> 6;
    now = 0;
    load = 1;
  }
  if (now == total) {
    memcpy(block, b[now], tail);
    res = tail;
    tail = 0;
  } else {
    memcpy(block, b[now++], 64);
    res = 64;
  }
  return res;
}