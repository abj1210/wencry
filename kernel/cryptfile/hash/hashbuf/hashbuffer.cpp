#include "hashbuffer.h"
#include <string.h>
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
构造函数:加载拼接的数据
block:拼接块
fp:输入文件指针
*/
buffer64::buffer64(u8_t *block, FILE *fp) : fp(fp), now(0) {
  memcpy(b[0], block, 64);
  u32_t sum = fread(b[1], 1, (HBUF_SZ - 1) << 6, fp);
  tail = sum & 0x3f;
  total = (sum >> 6) + 1;
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