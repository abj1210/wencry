#include "hashbuffer.h"
#include <string.h>
/*
构造函数:加载拼接的数据
block:拼接块
fsize:文件大小
fp:输入文件指针
*/
filebuffer64::filebuffer64(FILE *fp, const std::function<void(std::string, double)> &printload, size_t fsize, u8_t *block) : fp(fp), now(0), has_extra(block != NULL),
                                                                                                                             total_size(fsize == 0 ? 1 : fsize), now_size(0)
{
  if (block != NULL)
    memcpy(extra_entry, block, 64);
  u32_t sum = fread(b, 1, HBUF_SZ << 6, fp);
  tail = sum & 0x3f;
  total = (sum >> 6);
  printload("Hash", 100.0 * ((double)sum / (double)(total_size)));
};
/*
read_buffer:从缓冲区读取64B数据
block:读取数据的地址
return:读取的字节数
*/
u32_t filebuffer64::read_buffer64(u8_t *block, const std::function<void(std::string, double)> &printload)
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
    printload("Hash", 100.0 * ((double)sum / (double)(total_size)));
  }
  u32_t load_size = (now >= total) ? tail : 64;
  if (now == total)
    tail = 0;
  memcpy(block, b[now++], load_size);
  return load_size;
};