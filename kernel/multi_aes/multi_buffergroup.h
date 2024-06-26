#ifndef MBG
#define MBG

#include <condition_variable>
#include <mutex>
#include <iostream>
#include <string.h>
typedef unsigned char u8_t;
typedef unsigned int u32_t;
typedef unsigned long long u64_t;

#define COND_WAIT                                \
  std::unique_lock<std::mutex> locker(filelock); \
  while (turn != id)                             \
    cv[id].wait(locker);
#define COND_RELEASE                          \
  turn = (turn == (size - 1)) ? 0 : turn + 1; \
  cv[turn].notify_one();                      \
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
  static const u32_t sum = 0x1000000;

private:
  u8_t b[BUF_SZ][0x10];
  u32_t total, now;
  u8_t tail, pad;
  FILE *fin, *fout;
  bool ispadding;
  bool isfinal;

public:
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
  u32_t update_buffer(bool write, bool &over);
  /*
  bufferover:缓冲区和文件是否读取完毕
  return:若为0则未读取完毕,否则已读取完毕
  */
  bool buffer_over() const { return (now >= total) && isfinal; };
  /*
  fin_empty:判断缓冲区是否为空
  return:若为空返回真否则返回假
  */
  bool fin_empty() const { return (total == 0) && (tail == 0); };
  void final_write();
};
enum bufstate_t
{
  EMPTY,
  UPDATING,
  READY,
  INV
};
/*
bufferctrl:缓冲区状态控制类
lock:互斥锁
cv:条件变量
state:缓冲区状态(EMPTY:缓冲区为空 UPDATING:缓冲区正在更新 READY:缓冲区更新完毕 INV:缓冲区不可用)
*/
class bufferctrl
{
  static u8_t live_num;
  enum bufstate_t state;
  std::mutex lock;
  std::condition_variable cv;

public:
  bufferctrl() : state(EMPTY){live_num++;};
  bool cmpstate(const enum bufstate_t state) const { return this->state == state; };
  static bool haslive(){return live_num != 0;};
  void wait_ready();
  void wait_update();
  void set_ready();
  void set_update();
  void set_inv();
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
  bufferctrl *ctrl;
  u32_t turn;
  u64_t now_size, total_size;
  u32_t size;
  bool no_echo;
  bool over;
  buffergroup() : buflst(NULL), turn(0), now_size(0), over(false){};
  ~buffergroup()
  {
    delete[] buflst;
    delete[] ctrl;
  };
  void printload(const u8_t id, const size_t size);
  void buffer_update();
  void final_update();

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