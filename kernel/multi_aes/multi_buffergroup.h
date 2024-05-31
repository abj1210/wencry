#ifndef MBG
#define MBG

#include <condition_variable>
#include <mutex>
#include <iostream>
#include <string.h>
typedef unsigned char u8_t;
typedef unsigned int u32_t;

#define COND_WAIT                                \
  std::unique_lock<std::mutex> locker(filelock); \
  while (turn != id)                             \
    cond.wait(locker);

#define COND_RELEASE                          \
  turn = (turn == (size - 1)) ? 0 : turn + 1; \
  cond.notify_all();                          \
  locker.unlock();
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
class iobuffer
{
public:
  static const u32_t BUF_SZ = 0x100000;

private:
  u8_t b[BUF_SZ][0x10];
  u32_t total, now;
  u8_t tail, pad;
  FILE *fin, *fout;
  bool ispadding;

public:
  void init(FILE *fin, FILE *fout, bool ispadding)
  {
    this->fin = fin;
    this->fout = fout;
    this->ispadding = ispadding;
  };
  /*
  get_entry:获取当前缓冲区单元表项
  return:返回的表项地址
  */
  u8_t *get_entry() { return (now < total) ? b[now++] : NULL; };
  u32_t update_buffer(bool write, bool &over);
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
  void final_write();
};
/*
buffergroup:用于多线程的缓冲区组
buflst:缓冲区数组指针
size:缓冲区个数
fileaccess:控制相应序号缓冲区文件读写的互斥锁序列
*/
class buffergroup
{
  iobuffer *buflst;
  const u32_t size;
  u32_t turn;
  std::mutex filelock;
  std::condition_variable cond;
  bool over, no_echo;
  buffergroup(u32_t size, bool no_echo);
  ~buffergroup() { delete[] buflst; };

  static buffergroup *instance;
  static std::mutex mtx;

public:
  buffergroup(const buffergroup &) = delete;
  buffergroup &operator=(const buffergroup &) = delete;

  static buffergroup *get_instance(u32_t size = 4, bool no_echo = false);
  static void del_instance();

  void load_files(FILE *fin, FILE *fout, bool ispadding);
  void printload(const u8_t id, const size_t size);
  u8_t *require_buffer_entry(const u8_t id) { return buflst[id].get_entry(); };
  bool update_lst(const u8_t id);
  bool judge_over(const u8_t id);
};
#endif