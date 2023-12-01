#ifndef BUF
#define BUF

#include <stdio.h>
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
  static const unsigned BUF_SZ = 0x100000;

private:
  unsigned char b[BUF_SZ][0x10];
  unsigned int total;
  unsigned int now;
  unsigned char tail;
  FILE *fin, *fout;

public:
  bool load_files(FILE *fin, FILE *fout);
  unsigned char *get_entry();
  unsigned int update_buffer();
  bool buffer_over();
  bool fin_empty();
  unsigned int final_write(int tailin);
};

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
  static const unsigned HBUF_SZ = 0x80000;
  unsigned char b[HBUF_SZ][0x40];
  unsigned int total;
  unsigned int now;
  unsigned char tail;
  FILE *fp;

public:
  buffer64(FILE *fp);
  unsigned int read_buffer64(unsigned char *block);
};

#endif