#ifndef MBG
#define MBG

#include <condition_variable>
#include <mutex>
#include <string.h>
#include <string>
#include <functional>
#include <thread>
#include <chrono>
#include <cstdio>
typedef unsigned char u8_t;
typedef unsigned int u32_t;
typedef unsigned long long u64_t;

/*################################
  线程事件日志(PROFILE_THREADS 开关)
  记录读/工作/写/哈希线程的关键事件及时间戳到 threads.csv,
  用于离线分析流水线各线程的活跃/阻塞情况。
  事件:LOAD_BEGIN/LOAD_END(读线程),AES_BEGIN/AES_END(工作线程),WRITE_BEGIN/WRITE_END(写线程)
################################*/
#ifdef PROFILE_THREADS
extern thread_local const char *g_thread_role;
class ThreadProfiler
{
  FILE *out;
  std::mutex mtx;
  u64_t t0;

  static u64_t now_us()
  {
    return (u64_t)std::chrono::duration_cast<std::chrono::microseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
  }

public:
  static ThreadProfiler &inst()
  {
    static ThreadProfiler p;
    return p;
  }
  ThreadProfiler() : out(fopen("threads.csv", "w")), t0(now_us())
  {
    if (out)
      fprintf(out, "role,event,param,us\n");
  }
  ~ThreadProfiler()
  {
    if (out)
      fclose(out);
  }
  void log(const char *ev, u32_t param)
  {
    std::lock_guard<std::mutex> lk(mtx);
    if (out)
      fprintf(out, "%s,%s,%u,%llu\n", g_thread_role ? g_thread_role : "?", ev,
              (unsigned)param, (unsigned long long)(now_us() - t0));
  }
};
#define PROF_LOG(ev, param) ThreadProfiler::inst().log(ev, (u32_t)(param))
#else
#define PROF_LOG(ev, param)
#endif

/*################################
  流水线缓冲组
################################*/

/*
pipe_mode:流水线模式
PIPE_ENCRYPT:加密(读明文->AES->写密文,HASH读PROCESSED密文)
PIPE_DECRYPT:解密(HASH读LOADED密文->AES->写明文)
PIPE_VERIFY:仅验证(读密文->HASH,不AES不写)
*/
enum pipe_mode
{
  PIPE_ENCRYPT,
  PIPE_DECRYPT,
  PIPE_VERIFY
};

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
bufstate_t:缓冲区状态(统一流水线)
EMPTY:空闲,可装载
LOADED:已装载(密文/明文就绪)
CLAIMED:已被工作线程认领
PROCESSED:已处理完毕(AES完成)
HASHED:已由HASH线程读入HMAC
流转:
  加密: EMPTY->LOADED->CLAIMED->PROCESSED->HASHED->EMPTY
  解密: EMPTY->LOADED->HASHED->CLAIMED->PROCESSED->EMPTY
  验证: EMPTY->LOADED->EMPTY(HASH读完即回收)
*/
enum bufstate_t
{
  EMPTY,
  LOADED,
  CLAIMED,
  PROCESSED,
  HASHED
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
  data_len:缓冲区实际数据字节数(密文/明文长度,末块含填充)
  return:字节数
  */
  u32_t data_len() const { return total << 4; };
  /*
  load_buffer:从文件装载缓冲区(同步fread)
  fin:输入文件
  ispadding:是否填充(加密为true,解密/验证为false)
  return:装载状态
  */
  loadstate_t load_buffer(FILE *fin, bool ispadding);
  /*
  export_buffer:将缓冲区内容写入文件(同步fwrite),返回实际写出的字节数
  fout:输出文件
  ispadding:是否填充
  return:写出的字节数
  */
  u32_t export_buffer(FILE *fout, bool ispadding);
};

/*
buffergroup:统一多线程流水线缓冲组
采用"读线程--HASH线程--(工作线程)--写线程"流水线,加密/解密/验证三种模式共用:
  - 加密:读明文->AES->写密文;HASH线程读AES后的PROCESSED密文计算HMAC。
  - 解密:读密文;HASH线程读LOADED密文计算HMAC(先于AES覆盖);AES->写明文。
  - 验证:读密文;HASH线程读LOADED密文计算HMAC,读完即回收;不AES不写。
chunk k 固定装入 buf[k%size],由工作线程 (k%total_threads) 处理,写线程按序号顺序写出。
读线程负责背压(等待目标缓冲为EMPTY),保证有界缓冲与不死锁。
*/
class buffergroup
{
  static const u32_t MAX_BUF = 24;

  iobuffer *buflst;
  bufstate_t state[MAX_BUF];
  int thread_id_tag[MAX_BUF];   // 缓冲所属工作线程(块序决定,装载完成时写入)
  int thread_seq_tag[MAX_BUF];  // 块序号(单调递增,保证工作线程按序处理)
  u32_t size, total_threads;    // 缓冲个数, 工作线程数
  FILE *fin, *fout;
  pipe_mode mode;               // 流水线模式
  bool ispadding;               // 加密为true, 解密/验证为false
  bool over;             // 读线程已到达EOF
  bool read_done;        // 读线程已结束
  u32_t total_chunks;    // 装载的总块数

  std::function<void(const u8_t *, size_t)> hash_feed;  // HASH线程喂入HMAC的回调

  std::mutex mtx;
  std::condition_variable cv_empty, cv_loaded, cv_processed, cv_hash;

  buffergroup() : buflst(NULL), size(0), mode(PIPE_ENCRYPT), ispadding(true), over(false), read_done(false), total_chunks(0) {};
  ~buffergroup()
  {
    delete[] buflst;
  };

  static buffergroup *instance;
  static std::mutex mtx_singleton;

  void set_thread_tag(u8_t buffer_id, u8_t thread_id);
  bool remove_thread_tag(u8_t buffer_id);
  bool judge_buffer_loaded(u8_t thread_id);
  u8_t assign_buffer_id(u8_t thread_id);
  bool judge_buffer_full(u8_t next, u8_t thread_id, u8_t buffer_id);

public:
  buffergroup(const buffergroup &) = delete;
  buffergroup &operator=(const buffergroup &) = delete;
  static buffergroup *get_instance();
  static void del_instance();
  u8_t set_buffergroup(u32_t size, u32_t total_threads, FILE *fin, FILE *fout, pipe_mode mode);
  void set_hash_feed(const std::function<void(const u8_t *, size_t)> &feed) { hash_feed = feed; };
  pipe_mode get_mode() const { return mode; };

  /* 工作线程接口 */
  u8_t wait_loaded(const u8_t thread_id);
  bool stop_worker(const u8_t buffer_id);
  u8_t *get_entry(const u8_t buffer_id);
  bool finish_chunk(const u8_t buffer_id);

  /* 读线程 */
  void run_read(const std::function<void(std::string, size_t)> &printload);
  /* HASH线程(加密读PROCESSED,解密/验证读LOADED) */
  void run_hash(const std::function<void(std::string, size_t)> &printload);
  /* 写线程 */
  void run_write(const std::function<void(std::string, size_t)> &printload);
};
#endif
