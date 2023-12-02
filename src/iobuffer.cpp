#include "util.h"
#include <stdlib.h>
#include <string.h>
/*
load_files:设定输入输出文件并初始化缓冲区
fin:输入文件地址
fout:输出文件地址
r_buf:随机缓冲哈希
return:是否成功装载数据
*/
bool iobuffer::load_files(FILE *fin, FILE *fout, u8_t *r_buf) {
  this->fin = fin;
  this->fout = fout;
  memcpy(this->r, r_buf, 16);
  u32_t sum = fread(b, 1, BUF_SZ << 4, fin);
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
u8_t *iobuffer::get_entry() {
  if ((now < total) || ((now == total) && (tail != 0))) {
    *(u64_t *)b[now] ^= ld[0];
    *((u64_t *)b[now] + 1) ^= ld[1];
    return b[now++];
  } else
    return NULL;
}
/*
update_buffer:保存缓冲区数据并更新缓冲区
return:重新读入的字节数
*/
u32_t iobuffer::update_buffer() {
  u32_t sum = BUF_SZ << 4;
  fwrite(b, 1, sum, fout);
  sum = fread(b, 1, sum, fin);
  tail = sum & 0xf;
  total = sum >> 4;
  now = 0;
  return sum;
}
/*
final_write:将缓冲区内容保存到文件并关闭缓冲区
tailin:最后一表项中要保存的字节数
return:最后一表项装载的字节数
*/
u32_t iobuffer::final_write(int tailin) {
  fwrite(b, 1, ((now - 1) << 4) + tailin, fout);
  return tail == 0 ? 16 : tail;
}
/*
构造函数:加载数据
fp:输入文件指针
*/
buffer64::buffer64(FILE *fp) : fp(fp), now(0) {
  u32_t sum = fread(b, 1, HBUF_SZ << 6, fp);
  tail = sum & 0x3f;
  total = sum >> 6;
}
/*
read_buffer:从缓冲区读取64B数据
block:读取数据的地址
return:读取的字节数
*/
u32_t buffer64::read_buffer64(u8_t *block) {
  if (now == HBUF_SZ) {
    u32_t sum = fread(b, 1, HBUF_SZ << 6, fp);
    tail = sum & 0x3f;
    total = sum >> 6;
    now = 0;
  }
  if (now == total) {
    memcpy(block, b[now], tail);
    u32_t res = tail;
    tail = 0;
    return res;
  } else {
    memcpy(block, b[now++], 64);
    return 64;
  }
}