#ifndef MUL
#define MUL
#include "aesmode.h"
#include "multi_buffergroup.h"
#include <stdio.h>
#include <thread>
#include <functional>
typedef unsigned char u8_t;
/*
multicry_master:多线程调度器
run_multicry 按流水线模式启动线程:加密/解密启动工作线程+写线程+HASH线程,
验证仅启动HASH线程(不AES不写),配合 buffergroup 的"读--HASH--AES--写"统一流水线。
threads[THREAD_MAX]:工作线程句柄数组
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
