#include "multi_buffergroup.h"
#include <string>
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#endif

#ifdef PROFILE_THREADS
thread_local const char *g_thread_role = NULL;
#endif

/*################################
  模块概述:统一读--HASH--(AES)--写流水线
  加密/解密/验证三种模式共用同一流水线与HASH线程:
    - 加密:  EMPTY --读--> LOADED --AES--> CLAIMED --> PROCESSED --HASH--> HASHED --写--> EMPTY
    - 解密:  EMPTY --读--> LOADED --HASH--> HASHED --AES--> CLAIMED --> PROCESSED --写--> EMPTY
    - 验证:  EMPTY --读--> LOADED --HASH(读完即回收)--> EMPTY
  缓冲运行时按需动态分配,维护空闲池 idle_pool 与工作池 work_pool:
    读线程从空闲池取 buffer(空则 new),装满后按全局序号 seq 加入工作池;
    HASH线程按 seq 递增消费密文;工作线程按 seq%total_threads 路由领取最小 seq 的块;
    写线程按 seq 递增写出并回收 buffer 到空闲池(空闲池满/超时则释放)。
  统一序号 seq 取代原 threadid/seq 双标志:序号既决定顺序,又通过 seq%total_threads 推导归属线程。
  终止:读线程读到 EOF 后置 read_done 并记录 total_chunks;HASH线程消费完所有块后退出;
        写线程写完 total_chunks 个 chunk 后退出;工作线程在无任务(指针哨兵 NULL)后退出。
  同步:单一 mtx + 单一 cv(所有状态变更 notify_all,等待方用谓词自旋);fread/fwrite 在锁外执行。
  内存回收:读取完成后,写线程(验证模式为HASH线程)不再归还空闲池而直接释放并清空空闲池,
        保证流水线结束后内存自动收敛;del_instance 兜底释放。
  死锁安全:流水线为读->HASH->AES->写单向 DAG,各线程等待的是下游进展,无环。
################################*/



/*################################
  缓冲组管理
################################*/

buffergroup *buffergroup::instance = NULL;
std::mutex buffergroup::mtx_singleton;

/*
steady_us:steady_clock 微秒时间戳(用于空闲池超时判定)
return:自进程启动以来的微秒数
*/
u64_t buffergroup::steady_us()
{
  return (u64_t)std::chrono::duration_cast<std::chrono::microseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

/*
get_instance:获取单例实例(双重检查锁定,线程安全)
return:全局唯一的 buffergroup 实例
*/
buffergroup *buffergroup::get_instance()
{
  if (instance == NULL)
  {
    std::lock_guard<std::mutex> lock(mtx_singleton);
    if (instance == NULL)
      instance = new buffergroup();
  }
  return instance;
};
/*
del_instance:删除实例(兜底释放所有池内 buffer)
*/
void buffergroup::del_instance()
{
  if (instance != NULL)
  {
    std::lock_guard<std::mutex> lock(mtx_singleton);
    if (instance != NULL)
    {
      delete instance;
      instance = NULL;
    }
  }
};
/*
set_buffergroup:设置缓冲区组选项与流水线模式
total_threads:工作线程数
fin:输入文件
fout:输出文件(验证模式可为NULL)
mode:流水线模式(加密/解密/验证)
*/
void buffergroup::set_buffergroup(u32_t total_threads, pipe_mode mode)
{
  std::lock_guard<std::mutex> lock(mtx);
  this->total_threads = total_threads;
  this->mode = mode;
  this->total_chunks = 0;
  this->read_done = false;
  sweep_idle_locked();
  for (auto &kv : work_pool)
    delete kv.second;
  work_pool.clear();
};

/*################################
  加锁辅助函数(均要求持有 mtx)
################################*/
/*
has_claimable_locked:是否存在属于本线程且处于就绪态的块
thread_id:工作线程标号
ready:就绪状态(加密 LOADED / 解密 HASHED)
*/
bool buffergroup::has_claimable_locked(u8_t thread_id, bufstate_t ready) const
{
  for (auto &kv : work_pool)
  {
    iobuffer *b = kv.second;
    if (b->seq % total_threads == thread_id && b->state == ready)
      return true;
  }
  return false;
}
/*
worker_pending_locked:本线程是否仍有未处理完的块(未到 PROCESSED)
thread_id:工作线程标号
解密场景下 LOADED(待HASH)也计入 pending,防止工作线程提前退出遗弃该块。
*/
bool buffergroup::worker_pending_locked(u8_t thread_id) const
{
  for (auto &kv : work_pool)
  {
    iobuffer *b = kv.second;
    if (b->seq % total_threads == thread_id && b->state != PROCESSED)
      return true;
  }
  return false;
}
/*
claim_locked:领取本线程序号最小的就绪块并置为 CLAIMED
thread_id:工作线程标号
ready:就绪状态
return:领取到的 buffer;无则返回 NULL(退出哨兵)
*/
iobuffer *buffergroup::claim_locked(u8_t thread_id, bufstate_t ready)
{
  iobuffer *best = NULL;
  u64_t min_seq = ~0ULL;
  for (auto &kv : work_pool)
  {
    iobuffer *b = kv.second;
    if (b->seq % total_threads == thread_id && b->state == ready && b->seq < min_seq)
    {
      min_seq = b->seq;
      best = b;
    }
  }
  if (best)
    best->state = CLAIMED;
  return best;
}
/*
chunk_ready_locked:指定序号的块是否已处于目标状态(HASH/写线程按序消费用)
seq:块序号
ready:目标状态
return:该块存在且状态为 ready 返回 true
*/
bool buffergroup::chunk_ready_locked(u64_t seq, bufstate_t ready) const
{
  auto it = work_pool.find(seq);
  return it != work_pool.end() && it->second->state == ready;
}
/*
sweep_idle_locked:清空空闲池(释放全部空 buffer)
*/
void buffergroup::sweep_idle_locked()
{
  for (auto *b : idle_pool)
    delete b;
  idle_pool.clear();
}
/*
recycle_locked:回收已消费的 buffer
buf:待回收 buffer
读取完成后(read_done)不再复用,直接释放并清空空闲池;
读取进行中则淘汰空闲超时的 buffer,空闲池满则释放本 buffer,否则置 EMPTY 归还空闲池。
*/
void buffergroup::recycle_locked(iobuffer *buf)
{
  if (read_done)
  {
    delete buf;
    sweep_idle_locked();
    return;
  }
  u64_t now = steady_us();
  while (!idle_pool.empty() && (now - idle_pool.front()->idle_ts) > (u64_t)IDLE_TIMEOUT_MS * 1000ULL)
  {
    delete idle_pool.front();
    idle_pool.pop_front();
  }
  if ((u32_t)idle_pool.size() >= IDLE_POOL_MAX)
  {
    delete buf;
    return;
  }
  buf->state = EMPTY;
  buf->idle_ts = now;
  idle_pool.push_back(buf);
}

/*################################
  工作线程接口
################################*/
/*
wait_loaded:等待一个属于本线程的可领取块并领取(置CLAIMED)
thread_id:工作线程标号
return:领取到的 buffer;无任务返回 NULL 哨兵
*/
iobuffer *buffergroup::wait_loaded(const u8_t thread_id)
{
  bufstate_t ready = (mode == PIPE_ENCRYPT) ? LOADED : HASHED;
  std::unique_lock<std::mutex> locker(mtx);
  cv.wait(locker, [&] {
    return has_claimable_locked(thread_id, ready) ||
           (read_done && !worker_pending_locked(thread_id));
  });
  return claim_locked(thread_id, ready);
}

/*
finish_chunk:标记本块已处理完毕(AES完成)
buffer:缓冲
*/
void buffergroup::finish_chunk(iobuffer *buffer)
{
  std::lock_guard<std::mutex> locker(mtx);
  buffer->state = PROCESSED;
  cv.notify_all();
}

/*
wait_unhashed:HASH线程等待指定序号的块进入目标状态
next:块序号
return:该块 buffer;读取完成且无更多块返回 NULL(退出哨兵)
目标状态:加密 PROCESSED(AES后密文),解密/验证 LOADED(AES前密文)
*/
iobuffer *buffergroup::wait_unhashed(u64_t next){
  std::unique_lock<std::mutex> locker(mtx);
  bufstate_t target = (mode == PIPE_ENCRYPT) ? PROCESSED : LOADED;
  cv.wait(locker, [&] { return chunk_ready_locked(next, target) || (read_done && next == total_chunks); });
  if (read_done && next == total_chunks)
  {
    sweep_idle_locked(); // 读取已完成,清理空闲池残留(验证模式无写线程,由此兜底)
    return NULL;
  }
  return work_pool[next];
}

/*
finish_hashing:HASH线程消费完一个块的密文后推进其状态
buffer:该块
验证模式:从工作池移除并回收(读完即释放);
加密/解密:置 HASHED 交给下一级(AES 或写)。
*/
void buffergroup::finish_hashing(iobuffer *buffer){
  std::lock_guard<std::mutex> locker(mtx);
  u64_t next = buffer->seq;
  if (mode == PIPE_VERIFY)
  {
    work_pool.erase(next);
    recycle_locked(buffer); // 验证读完即回收
  }
  else
  {
    buffer->state = HASHED;
  }
  cv.notify_all();
}

/*
wait_idle_buffer:读线程获取一个空闲 buffer(空闲池空则动态 new)
return:空闲 buffer
读线程在工作池满(WORK_POOL_MAX)时阻塞,实现有界背压。
*/
iobuffer *buffergroup::wait_idle_buffer(){
  std::unique_lock<std::mutex> locker(mtx);
  iobuffer *buf;
  cv.wait(locker, [&] { return work_pool.size() < WORK_POOL_MAX; });
  if (idle_pool.empty())
    buf = new iobuffer;
  else
  {
    buf = idle_pool.front();
    idle_pool.pop_front();
  }
  return buf;
}

/*
finish_reading:读线程装入完成后把 buffer 注册进工作池
buffer:刚装入的 buffer
ls:装载状态(FULL/FINAL/NODATA)
next:本块全局序号
return:true 表示已读到末尾(FINAL/NODATA),读线程应退出;false 继续读
FULL:置 LOADED 入工作池;FINAL:入工作池并记录 total_chunks = next+1;
NODATA:空 buffer 直接释放,total_chunks = next。
*/
bool buffergroup::finish_reading(iobuffer *buffer, loadstate_t ls, u64_t next){
  std::lock_guard<std::mutex> locker(mtx);
    if (ls == FULL)
    {
      buffer->seq = next;
      buffer->state = LOADED;
      work_pool[next] = buffer;
      cv.notify_all();
      return false;
    }
    else
    {
      // FINAL:最后一个数据块(含填充); NODATA:无数据
      if (ls == FINAL)
      {
        buffer->seq = next;
        buffer->state = LOADED;
        work_pool[next] = buffer;
        total_chunks = next + 1; // 已装入块号为 next,块总数 = next + 1
      }
      else
      {
        delete buffer; // NODATA:空缓冲直接释放
        total_chunks = next; // 未装入新块,块总数 = next
      }
      read_done = true;
      cv.notify_all();
      return true;
    }
}

/*
wait_processed_buffer:写线程等待指定序号的块进入可写状态
next:块序号
return:该块 buffer;读取完成且无更多块返回 NULL(退出哨兵)
可写状态:加密 HASHED(HASH读完密文),解密 PROCESSED(AES完成)
*/
iobuffer *buffergroup::wait_processed_buffer(u64_t next){
  std::unique_lock<std::mutex> locker(mtx);
  bufstate_t ready = (mode == PIPE_ENCRYPT) ? HASHED : PROCESSED;
  cv.wait(locker, [&] { return chunk_ready_locked(next, ready) || (read_done && next == total_chunks); });
  if (read_done && next == total_chunks)
  {
    sweep_idle_locked(); // 兜底:读取完成后清空空闲池
    return NULL;
  }
  return work_pool[next];
}

/*
finish_writing:写线程写出一个块后,从工作池移除并回收
buffer:已写出的块
*/
void buffergroup::finish_writing(iobuffer *buffer){
  std::lock_guard<std::mutex> locker(mtx);
  work_pool.erase(buffer->seq);
  recycle_locked(buffer);
  cv.notify_all();
}