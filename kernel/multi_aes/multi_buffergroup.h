#ifndef MBG
#define MBG

#include <condition_variable>
#include <mutex>
#include <string.h>
#include <functional>
typedef unsigned char u8_t;
typedef unsigned int u32_t;
typedef unsigned long long u64_t;

/*
bufstate_t:缓冲区状态
EMPTY:空缓冲区
UPDATING:正在更新的缓冲区
READY:更新完毕的缓冲区
INV:无效缓冲区
*/
enum bufstate_t
{
  EMPTY,
  UPDATING,
  READY,
  INV
};
/*
loadstate_t:加载状态
FULL:全部加载
FINAL:最后一次加载
NODATA:无数据
*/
enum loadstate_t
{
  FULL,
  FINAL,
  NODATA
};

/*
iobuffer:用于aes的16B单元输入输出缓冲区
BUF_SZ:用于aes的16B单元缓冲区单元数量
sum:缓冲区总容量
b:缓冲区数组
total:缓冲区被填满的单元数量
now:将要被读写的单元索引
tail:未被填满的单元中数据的长度
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
  bool isfinal;

public:
  iobuffer() : total(0), now(0), tail(0), isfinal(false) {};
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
  loadstate_t load_buffer(FILE *fin, bool ispadding);
  void export_buffer(FILE *fout, bool ispadding);
};
/*
bufferctrl:缓冲区状态控制类
live_num:有效控制器数
lock:互斥锁
cv_ready:是否就绪条件变量
cv_update:是否更新条件变量
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
size:缓冲区个数
fin:输入文件
fout:输出文件
ispadding:是否填充
over:是否加载结束
*/
class buffergroup
{
  iobuffer *buflst;
  bufferctrl *ctrl;
  u32_t turn;
  u32_t size;
  FILE *fin, *fout;
  bool ispadding, over;
  buffergroup() : buflst(NULL), ctrl(NULL), turn(0), over(false) {};
  ~buffergroup()
  {
    delete[] buflst;
    delete[] ctrl;
  };
  bool turn_iter();
  void buffer_update(const std::function<void(std::string, size_t)> &printload);

  static buffergroup *instance;
  static std::mutex mtx;

public:
  buffergroup(const buffergroup &) = delete;
  buffergroup &operator=(const buffergroup &) = delete;
  static buffergroup *get_instance();
  static void del_instance();
  void set_buffergroup(u32_t size, FILE *fin, FILE *fout, bool ispadding);
  u8_t *require_buffer_entry(const u8_t id);
  void run_buffer(const std::function<void(std::string, size_t)> &printload);
};
#endif