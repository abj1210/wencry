#include "buffer.h"
/*
load_files:设定输入输出文件并初始化缓冲区
fin:输入文件地址
fout:输出文件地址
return:是否成功装载数据
*/
bool iobuffer::load_files(FILE *fin, FILE *fout) {
  this->fin = fin;
  this->fout = fout;
  u32_t sum = fread(b, 1, BUF_SZ << 4, fin);
  tail = sum & 0xf;
  total = sum >> 4;
  now = 0;
  return sum != 0;
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
u32_t iobuffer::final_write(u8_t tailin) {
  fwrite(b, 1, ((now - 1) << 4) + tailin, fout);
  return tail == 0 ? 16 : tail;
}