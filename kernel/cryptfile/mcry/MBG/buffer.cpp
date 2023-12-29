#include "buffer.h"
#include <string.h>
/*
load_files:设定输入输出文件并初始化缓冲区
fin:输入文件地址
fout:输出文件地址
over:加载是否结束
ispadding:是否为填充模式
return:是否成功装载数据
*/
bool iobuffer::load_files(FILE *fin, FILE *fout, bool &over, bool ispadding) {
  this->fin = fin;
  this->fout = fout;
  this->ispadding = ispadding;
  u32_t sum = BUF_SZ << 4;
  u32_t load = fread(b, 1, sum, fin);
  tail = load & 0xf;
  total = load >> 4;
  now = 0;
  if (ispadding && (load != sum) && (!over)) {
    u8_t padding = 16 - tail;
    memset(b[total] + tail, padding, padding);
    over = true;
    total++;
    return true;
  }
  return load != 0;
}
/*
update_buffer:保存缓冲区数据并更新缓冲区
over:加载是否结束
return:重新读入的字节数
*/
u32_t iobuffer::update_buffer(bool &over) {
  u32_t sum = BUF_SZ << 4;
  fwrite(b, 1, sum, fout);
  u32_t load = fread(b, 1, sum, fin);
  tail = load & 0xf;
  total = load >> 4;
  now = 0;
  if (ispadding && (load != sum) && (!over)) {
    u8_t padding = 16 - tail;
    memset(b[total] + tail, padding, padding);
    over = true;
    total++;
    return load + padding;
  }
  return load;
}
/*
final_write:将缓冲区内容保存到文件并关闭缓冲区
*/
void iobuffer::final_write() {
  u8_t padding = ispadding ? 0 : b[now - 1][15];
  fwrite(b, 1, (now << 4) - padding, fout);
}