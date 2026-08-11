#ifndef MUL
#define MUL
#include "aesmode.h"
#include "multi_buffergroup.h"
#include <stdio.h>
#include <thread>
#include <functional>
typedef unsigned char u8_t;
/*
multicry_master:多线程加解密调度器
run_multicry 创建 threads_num 个工作线程(每个处理一个独立IV的Aesmode),
配合 buffergroup 的"读线程--工作线程--写线程"三级流水线完成文件加解密。
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
