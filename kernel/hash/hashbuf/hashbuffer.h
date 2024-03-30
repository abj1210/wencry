#ifndef SBF
#define SBF
#include <stdio.h>
typedef unsigned char u8_t;
typedef unsigned int u32_t;
/*
HBUF_SZ:用于hash的64B单元缓冲区单元数量
buffer64:用于hash的64B单元缓冲区
b:缓冲区数组
total:缓冲区被填满的单元数量
now:将要被读写的单元索引
tail:未被填满的单元中数据的长度
load:是否被装载
*/
class buffer64 {
  static const u32_t HBUF_SZ = 0x80000;
  u8_t b[HBUF_SZ][0x40];
  u32_t total, now;
  u8_t tail;
  FILE *fp;

public:
  buffer64(FILE *fp);
  buffer64(u8_t *block, FILE *fp);
  u32_t read_buffer64(u8_t *block);
};
#endif
