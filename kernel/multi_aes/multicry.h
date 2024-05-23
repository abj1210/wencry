#ifndef MUL
#define MUL
#include "aesmode.h"
#include "multi_buffergroup.h"
#include <stdio.h>
#include <thread>
typedef unsigned char u8_t;
/*
多线程加解密抽象类
*/
class multicry_master
{
public:
  const u8_t THREADS_NUM;
  static const u8_t THREAD_MAX = 16;

private:
  std::thread threads[THREAD_MAX];
public:
  multicry_master(u8_t thread_num): THREADS_NUM(thread_num){};
  void run_multicry(buffergroup &iobuffer, Aesmode ** mode);
};


#endif