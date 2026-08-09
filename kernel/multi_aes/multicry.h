#ifndef MUL
#define MUL
#include "aesmode.h"
#include "multi_buffergroup.h"
#include <stdio.h>
#include <thread>
#include <functional>
typedef unsigned char u8_t;
/*
多线程加解密类
*/
class multicry_master
{
public:
  static const u8_t THREAD_MAX = 16;

private:
  std::thread threads[THREAD_MAX];

public:
  void run_multicry(u8_t threads_num, Aesmode **mode, const std::function<void(std::string, size_t)> &printload);
};

#endif
