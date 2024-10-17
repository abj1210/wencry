#include "hashbuffer.h"
#include <string.h>
#include <iostream>
#include <math.h>
#include <iomanip>
/*
构造函数:加载拼接的数据
block:拼接块
fsize:文件大小
fp:输入文件指针
*/
filebuffer64::filebuffer64(FILE *fp, bool no_echo, size_t fsize, u8_t *block) : fp(fp), no_echo(no_echo), now(0), has_extra(block != NULL),
total_size(fsize == 0 ? 1:fsize), now_size(0)
{
  if (block != NULL)
    memcpy(extra_entry, block, 64);
  u32_t sum = fread(b, 1, HBUF_SZ << 6, fp);
  tail = sum & 0x3f;
  total = (sum >> 6);
  if(sum != 0 && !no_echo)printload(sum);
};
/*
read_buffer:从缓冲区读取64B数据
block:读取数据的地址
return:读取的字节数
*/
u32_t filebuffer64::read_buffer64(u8_t *block)
{
  if (has_extra)
  {
    has_extra = false;
    memcpy(block, extra_entry, 64);
    return 64;
  }
  if (now == HBUF_SZ)
  {
    u32_t sum = fread(b, 1, HBUF_SZ << 6, fp);
    tail = sum & 0x3f;
    total = sum >> 6;
    now = 0;
    if(sum != 0 && !no_echo)printload(sum);
  }
  u32_t load_size = (now >= total) ? tail : 64;
  if (now == total)
    tail = 0;
  memcpy(block, b[now++], load_size);
  return load_size;
};
/*
printload:打印装载情况
id:装载数据的线程
size:装载大小
*/
void filebuffer64::printload(const size_t size)
{

  now_size += size;
  double percentage = 100.0 * ((double)now_size / (double)(total_size));
#ifndef GUI_ON
  std::cout << "Hash loaded  ";
  const int barWidth = 50; // 进度条的总宽度
  std::cout << "[";
  int pos = round(barWidth * percentage / 100.0);
  for (int i = 0; i < barWidth; ++i)
  {
    if (i < pos)
      std::cout << "=";
    else if (i == pos)
      std::cout << ">";
    else
      std::cout << " ";
  }
  std::cout << "] " << std::setw(12) << std::fixed << std::setprecision(2) << percentage << " %\r";
  std::cout.flush();
#else
  this->percentage = percentage;
#endif
}