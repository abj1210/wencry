#include "hashbuffer.h"
#include <string.h>

/*################################
  filebuffer64:为 Hashmaster::getFileHash 提供文件数据块流。
  构造函数一次性装载 32MB,并在构造时可拼接一个64字节"额外块"(HMAC的ipad块),
  使其先于文件数据进入哈希流。read_buffer64 每次返回一个64字节块,缓冲耗尽自动续读。
################################*/

/*
构造函数:加载拼接的数据
block:拼接块
printload:加载打印函数
fp:输入文件指针
*/
filebuffer64::filebuffer64(FILE *fp, const std::function<void(std::string, size_t)> &printload, u8_t *block) : has_extra(block != NULL), now(0), fp(fp)

{
  if (block != NULL)
    memcpy(extra_entry, block, 64);
  u32_t sum = fread(b, 1, HBUF_SZ << 6, fp);
  tail = sum & 0x3f;
  total = (sum >> 6);
  printload("Hash", sum);
};
/*
read_buffer:从缓冲区读取64B数据
block:读取数据的地址
printload:加载打印函数
return:读取的字节数
*/
u32_t filebuffer64::read_buffer64(u8_t *block, const std::function<void(std::string, size_t)> &printload)
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
    printload("Hash", sum);
  }
  u32_t load_size = (now >= total) ? tail : 64;
  if (now == total)
    tail = 0;
  memcpy(block, b[now++], load_size);
  return load_size;
};