#include "hashbuffer.h"
#include <string.h>
/*
构造函数:加载拼接的数据
block:拼接块
fp:输入文件指针
*/
filebuffer64::filebuffer64(FILE *fp, u8_t *block) : fp(fp), now(0), has_extra(block != NULL)
{
  if (block != NULL)
    memcpy(extra_entry, block, 64);
  u32_t sum = fread(b, 1, HBUF_SZ << 6, fp);
  tail = sum & 0x3f;
  total = (sum >> 6);
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
  }
  u32_t load_size = (now >= total) ? tail : 64;
  memcpy(block, b[now++], load_size);
  if (now == total)
    tail = 0;
  return load_size;
};