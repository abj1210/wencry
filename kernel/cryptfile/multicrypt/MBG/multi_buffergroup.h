#ifndef MBG
#define MBG

#include "buffer.h"
#include <condition_variable>
#include <mutex>

#define COND_WAIT                                                              \
  std::unique_lock<std::mutex> locker(filelock);                               \
  while (turn != id)                                                           \
    cond.wait(locker);

#define COND_RELEASE                                                           \
  turn = (turn == (size-1)) ? 0 : turn+1;                                                    \
  cond.notify_all();                                                           \
  locker.unlock();

/*
buffergroup:用于多线程的缓冲区组
buflst:缓冲区数组指针
size:缓冲区个数
fileaccess:控制相应序号缓冲区文件读写的互斥锁序列
*/
class buffergroup {
  iobuffer *buflst;
  const u32_t size;
  u32_t turn;
  std::mutex filelock;
  std::condition_variable cond;

public:
  buffergroup(u32_t size, FILE *fin, FILE *fout);
  /*
        析构函数:释放缓冲区组
  */
  ~buffergroup() { delete[] buflst; };
  /*
  require_buffer_entry:获取相应的缓冲区表项
  id:缓冲区索引
  return:相应缓冲区的待处理表项,若已处理完毕则输出NULL
  */
  u8_t *require_buffer_entry(const u8_t id) { return buflst[id].get_entry(); };
  bool update_lst(const u8_t id);
  bool judge_over(const u8_t id, u8_t &tail);
};
#endif