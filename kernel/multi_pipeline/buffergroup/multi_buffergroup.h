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
#include <queue>
#include <atomic>
typedef unsigned char u8_t;
typedef unsigned int u32_t;
typedef unsigned long long u64_t;

#include "sched_log.h"

/*################################
  线程时间线事件(已并入 SCHED_LOG)
  读/写/HASH/工作线程的关键事件记录到 sched_log.csv:
  LOAD_BEGIN/LOAD_END(读线程,seq=块号),AES_BEGIN/AES_END(工作线程,id=工作线程号),
  WRITE_BEGIN/WRITE_END(写线程,seq=块号)。
################################*/

/*################################
  缓冲池容量与超时宏
  WORK_PROCESSED_MAX : 工作池(LOADED)与已处理池(PROCESSED)共用的总在途块数上限,
                       满则读线程阻塞(背压)。
  IDLE_POOL_MAX      : 可复用空闲 buffer 数量上限,满则写线程直接释放。
  IDLE_TIMEOUT_MS    : 空闲 buffer 在空闲池中停留超过该时限(毫秒)即被释放。
################################*/
#ifndef WORK_PROCESSED_MAX
#define WORK_PROCESSED_MAX 16
#endif
#ifndef IDLE_POOL_MAX
#define IDLE_POOL_MAX 4
#endif
#ifndef IDLE_TIMEOUT_MS
#define IDLE_TIMEOUT_MS 1000
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
  inline static std::atomic<u64_t> s_next_id{0}; // 全局递增的 buffer 编号(供日志标识)

private:
  //数据成员
  u8_t b[BUF_SZ][0x10];     //缓冲区数组
  u32_t total, now, tail;   //缓冲区被填满的单元数量、将要被读写的单元索引、未被填满的单元中数据的长度
  bool isfinal;             //加载是否结束

public:
  //同步成员
  bool claimed;       //是否已被读线程认领(认领后仍留在空闲池中)
  u64_t seq;          //装载块的序号
  u64_t idle_ts;      //进入空闲池的时间戳(微秒,steady_clock)
  u64_t id;           //本缓冲区唯一编号(用于日志关联生成/销毁)

  iobuffer();
  ~iobuffer();
  u8_t *get_entry();
  u8_t *get_data();
  u32_t data_len() const;
  loadstate_t load_buffer(FILE *fin, bool ispadding);
  u32_t export_buffer(FILE *fout, bool ispadding);
};

/*
buffergroup:统一多线程流水线缓冲组
采用"读线程--(工作线程)--写线程"流水线,加密/解密/验证三种模式共用;
HMAC 由各工作线程就地计算(不再单设 HASH 线程):
  - 加密:读明文 -> 工作线程 AES -> 工作线程 HMAC -> 写密文。
  - 解密:读密文 -> 工作线程 HMAC -> 工作线程 AES -> 写明文。
  - 验证:读密文 -> 工作线程 HMAC,不 AES 不写。
缓冲按需动态分配,维护三个池:
  - 空闲池 idle_pool:可复用的空 buffer;读线程认领后仍留在空闲池中,直到读完(fread 期间不离开)。
  - 工作池 work_pool:已装载未领取(LOADED)的块,键为全局序号 seq。
  - 已处理池 processed_pool:AES/HMAC 完成待写的块(最小堆,按 seq 递增出队)。
工作池与已处理池共用一个总在途上限 WORK_PROCESSED_MAX。
每个 buffer 携带全局序号 seq,保证按序写;工作线程按 seq%total_threads 路由,领取本线程名下最小 seq 的块。
写线程按 seq 递增写出并回收 buffer 到空闲池(空闲池满/超时则释放);读取完成后写线程清理残留空 buffer。
*/
class buffergroup
{
  struct cmp{
    bool operator()(const iobuffer * a, const iobuffer * b){
      return a->seq > b->seq;
    }
  };
  std::deque<iobuffer *> idle_pool;         // 空闲池
  std::map<u64_t, iobuffer *> work_pool;    // 工作池(seq -> buffer)
  std::priority_queue<iobuffer *, std::vector<iobuffer *>, cmp> processed_pool;//已处理池，按序号递增
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
    while (!processed_pool.empty())
    {
      delete processed_pool.top();
      processed_pool.pop();
    }
  };

  static buffergroup *instance;
  static std::mutex mtx_singleton;

  static u64_t steady_us();

  /* 以下辅助函数均要求调用者持有 mtx */
  bool has_claimable_locked(const u64_t seq_next) const;
  iobuffer *claim_locked(const u64_t seq_next);
  bool worker_pending_locked(const u8_t thread_id) const;

  bool chunk_ready_locked(const u64_t seq) const;
  iobuffer *claim_processed();
  void recycle_locked(iobuffer *buf);

  void sweep_idle_locked();
  void release_buffer(iobuffer *buf);

public:
  buffergroup(const buffergroup &) = delete;
  buffergroup &operator=(const buffergroup &) = delete;
  static buffergroup *get_instance();
  static void del_instance();
  void set_buffergroup(u32_t total_threads, pipe_mode mode);

  /* 工作线程接口(指针语义,NULL 为退出哨兵) */
  bool stop_worker(iobuffer *buffer) { return buffer == NULL; };

  iobuffer *wait_loaded_buffer(const u8_t thread_id, const u64_t next);
  u64_t finish_processing(iobuffer *buffer);
  iobuffer *wait_cleared_buffer();
  bool finish_loading(iobuffer *buffer,const loadstate_t ls,const u64_t next);
  iobuffer *wait_processed_buffer(const u64_t next);
  void finish_clearing(iobuffer *buffer);

};
#endif
