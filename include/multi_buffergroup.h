#ifndef MBG
#define MBG

#include "util.h"

#ifdef MULTI_ENABLE
#include <condition_variable>
#include <mutex>
#include <thread>
/*
buffergroup:用于多线程的缓冲区组
buflst:缓冲区数组指针
size:缓冲区个数
fileaccess:控制相应序号缓冲区文件读写的互斥锁序列
*/
class buffergroup {
  struct iobuffer *buflst;
  unsigned int size;
  std::mutex *fileaccess;

public:
  buffergroup(unsigned int size, FILE *fin, FILE *fout);
  ~buffergroup();
  unsigned char *require_buffer_entry(unsigned int id);
  bool update_lst(unsigned int id);
  int judge_over(unsigned int id, unsigned int tail);
};
#endif

#endif