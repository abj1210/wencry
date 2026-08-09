#ifndef MBG
#define MBG

#include <condition_variable>
#include <mutex>
#include <string.h>
#include <string>
#include <functional>
typedef unsigned char u8_t;
typedef unsigned int u32_t;
typedef unsigned long long u64_t;

/*
loadstate_t:加载状态
FULL:全部加载
FINAL:最后一次加载(含数据)
NODATA:无数据
*/
enum loadstate_t
{
  FULL,
  FINAL,
  NODATA
};

/*
bufstate_t:缓冲区状态(三级流水线)
EMPTY:空闲,可装载
LOADED:已装载,工作线程可处理
PROCESSED:已处理完毕,写线程可导出
*/
enum bufstate_t
{
  EMPTY,
  LOADED,
  PROCESSED
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
  get_data:获取缓冲区数据起始地址
  return:数据起始地址
  */
  u8_t *get_data() { return &b[0][0]; };
  /*
  get_size:获取缓冲区装载大小
  return:返回的装载大小
  */
  u32_t get_size() { return (total << 4) | tail; };
  loadstate_t load_buffer(FILE *fin, bool ispadding);
  /*
  export_buffer:将缓冲区内容保存到文件,返回实际写出的字节数
  fout:输出文件
  ispadding:是否填充
  return:写出的字节数
  */
  u32_t export_buffer(FILE *fout, bool ispadding);
};

/*
buffergroup:多线程缓冲区组
采用"读线程--工作线程--写线程"三级流水线:
  EMPTY --(读线程 fread)--> LOADED --(工作线程就地AES)--> PROCESSED --(写线程 fwrite)--> EMPTY
chunk k 固定装入 buf[k%size],由工作线程 (k%size) 处理,写线程按序号顺序写出。
读线程负责背压(等待目标缓冲为EMPTY),保证有界缓冲与不死锁。
*/
class buffergroup
{
  static const u32_t MAX_BUF = 16;

  iobuffer *buflst;
  u8_t state[MAX_BUF];   // bufstate_t
  u32_t size;            // 缓冲个数 == 工作线程数
  FILE *fin, *fout;
  bool ispadding;

  bool over;             // 读线程已到达EOF
  bool read_done;        // 读线程已结束
  u32_t total_chunks;    // 装载的总块数

  std::function<void(const u8_t *, size_t)> hash_feed;  // 写线程导出密文时的哈希喂入钩子(加密融合用)

  std::mutex mtx;
  std::condition_variable cv_empty, cv_loaded, cv_processed;

  buffergroup() : buflst(NULL), size(0), over(false), read_done(false), total_chunks(0) {};
  ~buffergroup()
  {
    delete[] buflst;
  };

  static buffergroup *instance;
  static std::mutex mtx_singleton;

public:
  buffergroup(const buffergroup &) = delete;
  buffergroup &operator=(const buffergroup &) = delete;
  static buffergroup *get_instance();
  static void del_instance();
  void set_buffergroup(u32_t size, FILE *fin, FILE *fout, bool ispadding);
  void set_hash_feed(const std::function<void(const u8_t *, size_t)> &feed) { hash_feed = feed; };

  /* 工作线程接口 */
  void wait_loaded(const u8_t id);
  bool stop_worker(const u8_t id);
  u8_t *get_entry(const u8_t id);
  bool finish_chunk(const u8_t id);

  /* 读线程 */
  void run_read(const std::function<void(std::string, size_t)> &printload);
  /* 写线程 */
  void run_write(const std::function<void(std::string, size_t)> &printload);
};
#endif
