#ifndef BUF
#define BUF

#include <stdio.h>
typedef unsigned char u8_t;
typedef unsigned int u32_t;
/*
BUF_SZ:用于aes的16B单元缓冲区单元数量
iobuffer:用于aes的16B单元输入输出缓冲区
b:缓冲区数组
total:缓冲区被填满的单元数量
now:将要被读写的单元索引
tail:未被填满的单元中数据的长度
fin:读取文件的地址
fout:写入文件的地址
*/
class iobuffer {
public:
  static const u32_t BUF_SZ = 0x100000;
private:
  u8_t b[BUF_SZ][0x10];
  u32_t total, now;
  u8_t tail;
  FILE *fin, *fout;
public:
  bool load_files(FILE *fin, FILE *fout);
  /*
  get_entry:获取当前缓冲区单元表项
  return:返回的表项地址
  */
  u8_t *get_entry() {
    return ((now < total) || ((now == total) && (tail != 0))) ? b[now++] : NULL;
  };
  u32_t update_buffer();
  /*
  bufferover:缓冲区和文件是否读取完毕
  return:若为0则未读取完毕,否则已读取完毕
  */
  bool buffer_over() const { return (now >= total) && (total < BUF_SZ); };
  /*
  fin_empty:判断缓冲区是否为空
  return:若为空返回真否则返回假
  */
  bool fin_empty() const { return (total == 0) && (tail == 0); };
  u32_t final_write(u8_t tailin);
};

#endif