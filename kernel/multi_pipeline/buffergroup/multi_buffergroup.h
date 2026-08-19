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
#include <map>
#include <deque>
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
/*
ThreadProfiler:线程事件日志记录器(单例)
将各线程的流水线事件写入 threads.csv,用于离线分析线程活跃/阻塞情况。
out:CSV 文件句柄;mtx:串行化写;t0:相对时间基准(微秒)。
*/
class ThreadProfiler
{
  FILE *out;
  std::mutex mtx;
  u64_t t0;

  /* now_us:返回当前时刻相对 epoch 的微秒数 */
  static u64_t now_us()
  {
    return (u64_t)std::chrono::duration_cast<std::chrono::microseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
  }

public:
  /* inst:获取全局单例 */
  static ThreadProfiler &inst()
  {
    static ThreadProfiler p;
    return p;
  }
  /* ThreadProfiler:构造,打开 threads.csv 并写表头 */
  ThreadProfiler() : out(fopen("threads.csv", "w")), t0(now_us())
  {
    if (out)
      fprintf(out, "role,event,param,us\n");
  }
  /* ~ThreadProfiler:析构,关闭 CSV 文件 */
  ~ThreadProfiler()
  {
    if (out)
      fclose(out);
  }
  /* log:记录一条线程事件(加锁串行化写) */
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
  缓冲池容量与超时宏
  工作池:在途(读入->写出)buffer 的数量上限,满则读线程阻塞。
  空闲池:可复用空闲 buffer 的数量上限,满则写线程直接释放。
  IDLE_TIMEOUT_MS:空闲 buffer 在空闲池中停留超过该时限(毫秒)即被写线程释放。
################################*/
#define WORK_POOL_MAX 8
#define IDLE_POOL_MAX 4
#define IDLE_TIMEOUT_MS 1000

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
iobuffer类主要包括数据成员和同步成员。
数据成员负责承载数据和控制读取状态。其修改通过类的接口实现
同步成员负责保证缓冲区状态、装在序号等控制状态的同步。其修改由并发调度器统一控制
*/
class iobuffer
{
public:
  static const u32_t BUF_SZ = 0x100000; //用于aes的16B单元缓冲区单元数量
  static const u32_t sum = 0x1000000;   //缓冲区总容量

private:
  //数据成员
  u8_t b[BUF_SZ][0x10];     //缓冲区数组
  u32_t total, now, tail;   //缓冲区被填满的单元数量、将要被读写的单元索引、未被填满的单元中数据的长度
  bool isfinal;             //加载是否结束

public:
  //同步成员
  bufstate_t state;   //本缓冲区的流水线状态
  u64_t seq;          //装载块的序号
  u64_t idle_ts;      //进入空闲池的时间戳(微秒,steady_clock)

  iobuffer();
  u8_t *get_entry();
  u8_t *get_data();
  u32_t data_len() const;
  loadstate_t load_buffer(FILE *fin, bool ispadding);
  u32_t export_buffer(FILE *fout, bool ispadding);
};

/*
buffergroup:统一多线程流水线缓冲组
采用"读线程--HASH线程--(工作线程)--写线程"流水线,加密/解密/验证三种模式共用:
  - 加密:读明文->AES->写密文;HASH线程读AES后的PROCESSED密文计算HMAC。
  - 解密:读密文;HASH线程读LOADED密文计算HMAC(先于AES覆盖);AES->写明文。
  - 验证:读密文;HASH线程读LOADED密文计算HMAC,读完即回收;不AES不写。
缓冲按需动态分配,维护两个池:
  - 空闲池 idle_pool:可复用的空 buffer;读线程从空闲池取(空则 new)。
  - 工作池 work_pool:在途 buffer,键为全局块序号 seq。
每个 buffer 携带统一全局序号 seq,保证 HASH/写按序消费;
工作线程按 seq%total_threads 路由(保留AES链式模式所需的固定路由),按最小 seq 领取。
写线程写出后回收 buffer 到空闲池;空闲池满或空闲超时则直接释放;
读取完成后,写线程(验证模式为HASH线程)自动清理残留的空 buffer。
*/
class buffergroup
{
  std::deque<iobuffer *> idle_pool;         // 空闲池
  std::map<u64_t, iobuffer *> work_pool;    // 工作池(seq -> buffer)
  u32_t total_threads;                      // 工作线程数
  u64_t total_chunks;                       // 装载的总块数
  pipe_mode mode;                           // 流水线模式
  bool read_done;                           // 读线程已结束

  std::mutex mtx;
  std::condition_variable cv;

  buffergroup() : total_threads(0), total_chunks(0), mode(PIPE_ENCRYPT), read_done(false) {};
  ~buffergroup()
  {
    for (auto &kv : work_pool)
      delete kv.second;
    for (auto *b : idle_pool)
      delete b;
  };

  static buffergroup *instance;
  static std::mutex mtx_singleton;

  static u64_t steady_us();

  /* 以下辅助函数均要求调用者持有 mtx */
  iobuffer *claim_locked(u8_t thread_id, bufstate_t ready);
  bool has_claimable_locked(u8_t thread_id, bufstate_t ready) const;
  bool worker_pending_locked(u8_t thread_id) const;
  bool chunk_ready_locked(u64_t seq, bufstate_t ready) const;
  void recycle_locked(iobuffer *buf);
  void sweep_idle_locked();

public:
  buffergroup(const buffergroup &) = delete;
  buffergroup &operator=(const buffergroup &) = delete;
  static buffergroup *get_instance();
  static void del_instance();
  void set_buffergroup(u32_t total_threads, pipe_mode mode);

  /* 工作线程接口(指针语义,NULL 为退出哨兵) */
  iobuffer *wait_loaded(const u8_t thread_id);
  bool stop_worker(iobuffer *buffer) { return buffer == NULL; };
  void finish_chunk(iobuffer *buffer);
  iobuffer *wait_unhashed(u64_t next);
  void finish_hashing(iobuffer *buffer);
  iobuffer *wait_idle_buffer();
  bool finish_reading(iobuffer *buffer, loadstate_t ls, u64_t next);
  iobuffer *wait_processed_buffer(u64_t next);
  void finish_writing(iobuffer *buffer);

};
#endif
