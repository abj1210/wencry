#ifndef MBG
#define MBG

#include <condition_variable>
#include <mutex>
#include <iostream>
#include <string.h>
typedef unsigned char u8_t;
typedef unsigned int u32_t;
typedef unsigned long long u64_t;
enum bufstate_t
{
  EMPTY,
  UPDATING,
  READY,
  INV
};

enum loadstate_t
{
  FULL,
  FINAL,
  NO_DATA
};

/*
iobuffer:用于aes的16B单元输入输出缓冲区
BUF_SZ:用于aes的16B单元缓冲区单元数量
sum:缓冲区总容量
b:缓冲区数组
total:缓冲区被填满的单元数量
now:将要被读写的单元索引
tail:未被填满的单元中数据的长度
pad:填充所需的数据
fin:读取文件的地址
fout:写入文件的地址
ispadding:是否需要填充
isfinal:加载是否结束
*/
class iobuffer
{
public:
  static const u32_t BUF_SZ = 0x100000;
  static const u32_t sum = 0x1000000;

private:
  u8_t b[BUF_SZ][0x10];
  u32_t total, now, tail;
  FILE *fin, *fout;
  bool ispadding, isfinal;

public:
  /*
  init:初始化
  fin:读取文件的地址
  fout:写入文件的地址
  ispadding:是否需要填充
  */
  void init(FILE *fin, FILE *fout, bool ispadding)
  {
    this->isfinal = false;
    this->fin = fin;
    this->fout = fout;
    this->ispadding = ispadding;
  };
  /*
  get_entry:获取当前缓冲区单元表项
  return:返回的表项地址
  */
  u8_t *get_entry() { return (now < total) ? b[now++] : NULL; };
  /*
  get_size:获取缓冲区装载大小
  return:返回的装载大小
  */
  u32_t get_size() { return (total << 4) | tail; };
  loadstate_t load_buffer();
  void export_buffer();
};
/*
bufferctrl:缓冲区状态控制类
live_num:有效控制器数
lock:互斥锁
cv_ready:是否就绪条件变量
cv_update:是否更新条件变量
state:缓冲区状态(EMPTY:缓冲区为空 UPDATING:缓冲区正在更新 READY:缓冲区更新完毕 INV:缓冲区不可用)
*/
class bufferctrl
{
  static u8_t live_num;
  enum bufstate_t state;
  std::mutex lock;
  std::condition_variable cv_ready, cv_update;

public:
  bufferctrl() : state(EMPTY) { live_num++; };
  bool cmpstate(const enum bufstate_t state) const { return this->state == state; };
  static bool haslive() { return live_num != 0; };

  void wait_ready();
  void wait_update();
  void set_ready(bool load);
  void set_update();
};
/*
buffergroup:用于多线程的缓冲区组
buflst:缓冲区数组指针
ctrl控制器数组指针
turn:当前缓冲区序号
now_size:当前加载数据大小
total_size:总数据大小
size:缓冲区个数
no_echo:是否不回显
over:是否加载结束
*/
class buffergroup
{
public:
  int percentage;

private:
  iobuffer *buflst;
  bufferctrl *ctrl;
  u32_t turn;
  u64_t now_size, total_size;
  u32_t size;
  bool no_echo;
  bool over;
  buffergroup() : buflst(NULL), turn(0), now_size(0), over(false), percentage(-1) {};
  ~buffergroup()
  {
    delete[] buflst;
    delete[] ctrl;
  };
  bool turn_iter();
  void printload(const u8_t id, const size_t size);
  void buffer_update();

  static buffergroup *instance;
  static std::mutex mtx;

public:
  buffergroup(const buffergroup &) = delete;
  buffergroup &operator=(const buffergroup &) = delete;
  static buffergroup *get_instance();
  static void del_instance();

  void set_buffergroup(u32_t size, bool no_echo, FILE *fin, FILE *fout, bool ispadding, u64_t fsize);
  u8_t *require_buffer_entry(const u8_t id);
  void run_buffer();
};
#endif