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
################################*/
#ifndef WORK_PROCESSED_MAX
#define WORK_PROCESSED_MAX 16
#endif
#ifndef IDLE_POOL_MAX
#define IDLE_POOL_MAX 4
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
IoBuffer:用于aes的16B单元输入输出缓冲区
IoBuffer类主要包括数据成员和同步成员。
数据成员负责承载数据和控制读取状态。其修改通过类的接口实现
同步成员负责保证缓冲区状态、装在序号等控制状态的同步。其修改由并发调度器统一控制
*/
class IoBuffer
{
public:
  static const u32_t BUF_SZ = 0x100000; //用于aes的16B单元缓冲区单元数量
  static const u32_t sum = 0x1000000;   //缓冲区总容量
  inline static std::atomic<u64_t> s_next_id{0}; // 全局递增的 buffer 编号(供日志标识)

private:
  //数据成员
  u8_t b[BUF_SZ][0x10];     //缓冲区数组
  u32_t total, now;         //缓冲区被填满的单元数量、将要被读写的单元索引
  u64_t seq;          //装载块的序号
public:
  u64_t id;

  IoBuffer();
  ~IoBuffer();
  u8_t *getEntry();
  u8_t *getData();
  u32_t dataLen() const;
  u64_t get_seq() const;
  void set_seq(u64_t seq);
  loadstate_t loadBuffer(FILE *fin, bool ispadding);
  u32_t exportBuffer(FILE *fout, bool isfinal, bool ispadding);
};

/*
BufferGroup:统一多线程流水线缓冲组
采用"读线程--(工作线程)--写线程"流水线,加密/解密/验证三种模式共用;
HMAC 由各工作线程就地计算(不再单设 HASH 线程):
  - 加密:读明文 -> 工作线程 AES -> 工作线程 HMAC -> 写密文。
  - 解密:读密文 -> 工作线程 HMAC -> 工作线程 AES -> 写明文。
  - 验证:读密文 -> 工作线程 HMAC,不 AES 不写。
缓冲按需动态分配,维护三个池:
  - 空闲池 idle_pool(锁 mtxi):可复用的空 buffer;读线程认领时即移出,写完/验证完由写线程归还。
  - 工作池 work_pool:已装载未领取(LOADED)的块,键为全局序号 seq。
  - 已处理池 processed_pool:AES/HMAC 完成待写的块(最小堆,按 seq 递增出队)。
工作池与已处理池共用一个总在途上限 WORK_PROCESSED_MAX(锁 mtxwp),满则读线程阻塞(背压)。
每个 buffer 携带全局序号 seq,保证按序写;工作线程按 seq%total_threads 路由,只领取自己名下的块。
终止:读线程读到 FINAL/NODATA 后由 finishLoading 在锁内登记 total_chunks 并置 read_done,
      工作线程/写线程据此判定"不会再有本序号/更小序号的块",空指针即退出哨兵;
      写线程按 seq 递增写出 total_chunks 个块后退出,并把 buffer 归还空闲池。
内存收敛:read_done 之后写线程不再归还空闲池而是直接释放(空闲池满同样直接释放),
          并在流水线线程全部汇合后由 delInstance 兜底释放。
*/
class BufferGroup
{
  struct cmp{
    bool operator()(const IoBuffer * a, const IoBuffer * b){
      return a->get_seq() > b->get_seq();
    }
  };
  std::deque<IoBuffer *> idle_pool;         // 空闲池
  std::map<u64_t, IoBuffer *> work_pool;    // 工作池(seq -> buffer)
  std::priority_queue<IoBuffer *, std::vector<IoBuffer *>, cmp> processed_pool;//已处理池，按序号递增
  u32_t total_threads;                      // 工作线程数
  std::atomic<u64_t> total_chunks;          // 已装载的块总数(seq 取值 0..total_chunks-1)
  std::atomic<bool> read_done;              // 读线程已结束(不会再产生新块)

  std::mutex mtxi;                          // 保护 idle_pool
  std::mutex mtxwp;                         // 保护 work_pool/processed_pool/total_chunks/read_done 与 cvwp
  std::condition_variable cvwp;             // 流水线状态变化通知(work/processed/read_done)

  BufferGroup() : total_threads(0), total_chunks(0), read_done(false) {};
  ~BufferGroup()
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

  static BufferGroup *instance;
  static std::mutex mtx_singleton;
  void releaseBuffer(IoBuffer *buf);

public:
  BufferGroup(const BufferGroup &) = delete;
  BufferGroup &operator=(const BufferGroup &) = delete;
  static BufferGroup *getInstance();
  static void delInstance();
  void setBufferGroup(u32_t total_threads, [[maybe_unused]] pipe_mode mode);

  /* 退出哨兵判定:工作线程与写线程均以 NULL 表示"已无任务/已写完" */
  bool stopWorker(IoBuffer *buffer) { return buffer == NULL; };

  /* 读线程接口 */
  IoBuffer * recvIdlePool(u64_t seq);                          // 认领空闲 buffer(空则新建)并置序号 seq
  bool finishLoading(IoBuffer *buf, loadstate_t ls, u64_t next); // 登记已装载块(含背压);返回 true 表示已读到末尾

  /* 工作线程接口 */
  IoBuffer * recvWorkPool(u64_t next);                         // 领取本线程名下的块;NULL 为退出哨兵
  u64_t sendProcessedPool(IoBuffer * buf);                     // 处理完成移入已处理池,返回本线程下一个序号

  /* 写线程接口 */
  IoBuffer * recvProcessedPool(u64_t next);                    // 按序取待写块;NULL 为退出哨兵
  void sendIdlePool(IoBuffer * buf);                           // 归还空闲池(read_done 后/池满则释放)

  /* 是否为最后一块(末块含 PKCS7 填充,解密时需按填充长度截断) */
  bool getFinalBlock(u64_t seq) const
  {
    return read_done.load() && seq + 1 == total_chunks.load();
  }

};
#endif
