#include "multi_buffergroup.h"
#include <string>
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#endif

/*################################
  模块概述:统一读--(AES/HMAC)--写流水线
  加密/解密/验证三种模式共用同一流水线,HMAC 由各工作线程就地计算(不再单设 HASH 线程):
    - 加密:  EMPTY --读--> LOADED --工作线程AES/HMAC--> PROCESSED --写--> EMPTY
    - 解密:  EMPTY --读--> LOADED --工作线程HMAC/AES--> PROCESSED --写--> EMPTY
    - 验证:  EMPTY --读--> LOADED --工作线程HMAC--> PROCESSED --回收--> EMPTY
  缓冲运行时按需动态分配,维护三个池:空闲池 idle_pool、工作池 work_pool、已处理池 processed_pool:
    读线程从空闲池认领 buffer(空则 new),fread 装满后由 finishLoading 移入工作池;
    工作线程按 seq%total_threads 领取本线程名下的块,AES/HMAC 完成后移入已处理池;
    写线程按 seq 递增从已处理池取出写出,并回收 buffer 到空闲池(读取结束后直接释放)。
  统一序号 seq 取代原 threadid/seq 双标志:序号既决定顺序,又通过 seq%total_threads 推导归属线程。
  终止:读线程读到 FINAL/NODATA 后由 finishLoading 在锁内记录 total_chunks 并置 read_done;
        工作线程等不到自己名下的块、写线程写完 total_chunks 个块后,均收到 NULL 哨兵退出。
  同步:mtxwp 保护 work_pool/processed_pool/total_chunks/read_done 与 cvwp;mtxi 单独保护 idle_pool。
        fread/fwrite 在锁外执行;total_chunks 与 read_done 用原子量,供背压/回收路径无锁读取。
  背压:工作池+已处理池总在途块数达到 WORK_PROCESSED_MAX 时读线程阻塞。
  内存回收:读取完成后写线程不再归还空闲池而直接释放,内存随流水线结束收敛;delInstance 兜底释放。
  死锁安全:流水线为读->工作->写单向 DAG,各线程等待的是下游进展,无环。
################################*/



/*################################
  缓冲组管理
################################*/

BufferGroup *BufferGroup::instance = NULL;
std::mutex BufferGroup::mtx_singleton;

/*
getInstance:获取单例实例(双重检查锁定,线程安全)
return:全局唯一的 BufferGroup 实例
*/
BufferGroup *BufferGroup::getInstance()
{
  if (instance == NULL)
  {
    std::lock_guard<std::mutex> lock(mtx_singleton);
    if (instance == NULL)
      instance = new BufferGroup();
  }
  return instance;
};
/*
delInstance:删除实例(兜底释放所有池内 buffer)
*/
void BufferGroup::delInstance()
{
  if (instance != NULL)
  {
    std::lock_guard<std::mutex> lock(mtx_singleton);
    if (instance != NULL)
    {
      SCHED_LOG("?", "RUN_END", -1, -1, "", 0, 0, 0);
      delete instance;
      instance = NULL;
    }
  }
};
/*
setBufferGroup:重置缓冲区组状态并设置流水线模式(每轮加/解密开始时调用)
total_threads:工作线程数
mode:流水线模式(加密/解密/验证)
*/
void BufferGroup::setBufferGroup(u32_t total_threads, [[maybe_unused]] pipe_mode mode)
{
  std::lock_guard<std::mutex> lock(mtxwp);
  this->total_threads = total_threads;
  this->total_chunks.store(0);
  this->read_done.store(false);
  for (auto &kv : work_pool)
    releaseBuffer(kv.second);
  work_pool.clear();
  while (!processed_pool.empty())
  {
    releaseBuffer(processed_pool.top());
    processed_pool.pop();
  }
  SCHED_LOG("?", "RUN_START", -1, -1,
            (std::string((mode == PIPE_ENCRYPT) ? "ENCRYPT" : (mode == PIPE_DECRYPT) ? "DECRYPT" : "VERIFY") +
             ":" + std::to_string((unsigned)total_threads)).c_str(),
            0, 0, 0);
};

/*
releaseBuffer:释放一个 buffer(析构函数内记录 BUF_DELETE)
buf:待释放 buffer
*/
void BufferGroup::releaseBuffer(IoBuffer *buf)
{
  // 仅在开启调度日志时使用,普通构建下允许未使用
  [[maybe_unused]] u64_t id = buf->id;
  [[maybe_unused]] u64_t seq = buf->get_seq();
  delete buf;
  SCHED_LOG(g_sched_role, "BUF_DELETE_AFTER", (long long)id, (long long)seq, "", -1, -1, -1);
}

/*################################
  池操作
  锁约定:mtxi 只保护 idle_pool;mtxwp 保护 work_pool/processed_pool/total_chunks/read_done。
  两级锁互不嵌套(不存在 mtxi->mtxwp 或反向的持锁嵌套),因此不会死锁。
  日志中未知的池大小按约定记 -1。
################################*/

/*
recvIdlePool:读线程认领一个空闲 buffer
seq:该 buffer 将要承载的全局序号
return:可用 buffer(空闲池为空时新建)
*/
IoBuffer *BufferGroup::recvIdlePool(u64_t seq)
{
  std::unique_lock<std::mutex> locker(mtxi);
  SCHED_LOG(g_sched_role, "POP_IDLE_PRE", -1, (long long)seq, "EMPTY",
            -1, (int)idle_pool.size(), -1);
  IoBuffer *buf = NULL;
  if (idle_pool.empty())
  {
    buf = new IoBuffer;
  }
  else
  {
    buf = idle_pool.front();
    idle_pool.pop_front();
  }
  buf->set_seq(seq);
  SCHED_LOG(g_sched_role, "POP_IDLE", buf->id, (long long)seq, "EMPTY",
            -1, (int)idle_pool.size(), -1);
  return buf;
}

/*
finishLoading:读线程把装载完成的 buffer 登记进工作池(含背压等待)
buf:刚装载完成的 buffer
ls:装载状态(FULL/FINAL/NODATA)
next:该块序号
return:true 表示本线程已读到末尾(FINAL/NODATA),应退出;false 继续读
说明:NODATA 不产生块,该 buffer 直接释放;登记与置位 read_done 在同一把锁内完成,
      避免"已宣布读取结束、末块却还没进工作池"的空窗导致工作线程提前退出。
*/
bool BufferGroup::finishLoading(IoBuffer *buf, loadstate_t ls, u64_t next)
{
  std::unique_lock<std::mutex> locker(mtxwp);
  cvwp.wait(locker, [&] { return (work_pool.size() + processed_pool.size()) < WORK_PROCESSED_MAX; });
  if (ls == NODATA)
  {
    SCHED_LOG(g_sched_role, "LOADED_PRE", buf->id, (long long)next, "EMPTY",
              (int)work_pool.size(), -1, (int)processed_pool.size());
    releaseBuffer(buf);
  }
  else
  {
    SCHED_LOG(g_sched_role, "LOADED_PRE", buf->id, (long long)next, "LOADED",
              (int)work_pool.size(), -1, (int)processed_pool.size());
    work_pool.insert({next, buf});
    total_chunks.store(next + 1);
    SCHED_LOG(g_sched_role, "LOADED", buf->id, (long long)next, "LOADED",
              (int)work_pool.size(), -1, (int)processed_pool.size());
  }
  if (ls != FULL)
  {
    read_done.store(true);
    SCHED_LOG(g_sched_role, "READ_DONE", -1, (long long)next, "",
              (int)work_pool.size(), -1, (int)processed_pool.size());
  }
  cvwp.notify_all();
  return ls != FULL;
}

/*
recvWorkPool:工作线程领取本线程名下的块
next:本线程期望的块序号(初值=线程号,每次 += total_threads)
return:该块 buffer;NULL 表示本线程已无任务(退出哨兵)
说明:序号由读线程从 0 连续分配,因此本线程不会再等到任务的条件是
      "读取已结束 且 (期望序号已越界 或 工作池已空)"。
*/
IoBuffer *BufferGroup::recvWorkPool(u64_t next)
{
  std::unique_lock<std::mutex> locker(mtxwp);
  cvwp.wait(locker, [&] {
    return work_pool.find(next) != work_pool.end() ||
           (read_done.load() && (next >= total_chunks.load() || work_pool.empty()));
  });
  auto kv = work_pool.find(next);
  if (kv == work_pool.end())
    return NULL;
  SCHED_LOG(g_sched_role, "POP_WORK_PRE", kv->second->id, (long long)next, "LOADED",
            (int)work_pool.size(), -1, (int)processed_pool.size());
  IoBuffer *buf = kv->second;
  work_pool.erase(kv);
  SCHED_LOG(g_sched_role, "POP_WORK", buf->id, (long long)next, "CLAIMED",
            (int)work_pool.size(), -1, (int)processed_pool.size());
  cvwp.notify_all();
  return buf;
}

/*
sendProcessedPool:工作线程把处理完成的块移入已处理池
buf:处理完成的缓冲
return:本线程下一个期望序号
*/
u64_t BufferGroup::sendProcessedPool(IoBuffer *buf)
{
  std::unique_lock<std::mutex> locker(mtxwp);
  SCHED_LOG(g_sched_role, "PROCESSED_PRE", buf->id, (long long)buf->get_seq(), "CLAIMED",
            (int)work_pool.size(), -1, (int)processed_pool.size());
  processed_pool.push(buf);
  SCHED_LOG(g_sched_role, "PROCESSED", buf->id, (long long)buf->get_seq(), "PROCESSED",
            (int)work_pool.size(), -1, (int)processed_pool.size());
  cvwp.notify_all();
  return buf->get_seq() + total_threads;
}

/*
recvProcessedPool:写线程按序取待写块
next:期望的块序号(从 0 起依次递增)
return:该块 buffer;NULL 表示所有块都已写出(退出哨兵)
说明:只取走堆顶且序号正好等于 next 的块,保证输出顺序;
      绝不触碰空堆(读取结束且 next 越界时直接返回 NULL)。
*/
IoBuffer *BufferGroup::recvProcessedPool(u64_t next)
{
  std::unique_lock<std::mutex> locker(mtxwp);
  cvwp.wait(locker, [&] {
    return (!processed_pool.empty() && processed_pool.top()->get_seq() == next) ||
           (read_done.load() && next >= total_chunks.load());
  });
  if (processed_pool.empty() || processed_pool.top()->get_seq() != next)
    return NULL;
  SCHED_LOG(g_sched_role, "POP_PROCESSED_PRE", processed_pool.top()->id, (long long)next, "PROCESSED",
            (int)work_pool.size(), -1, (int)processed_pool.size());
  IoBuffer *buf = processed_pool.top();
  processed_pool.pop();
  SCHED_LOG(g_sched_role, "POP_PROCESSED", buf->id, (long long)next, "PROCESSED",
            (int)work_pool.size(), -1, (int)processed_pool.size());
  cvwp.notify_all();
  return buf;
}

/*
sendIdlePool:写线程归还 buffer
buf:待归还 buffer
说明:读取已结束(不会再读)时不再保留空闲 buffer,直接释放,内存随流水线结束收敛;
      空闲池满同样直接释放(内存上界 ≈ 在途上限 + 空闲池上限)。
*/
void BufferGroup::sendIdlePool(IoBuffer *buf)
{
  std::unique_lock<std::mutex> locker(mtxi);
  if (read_done.load() || (u32_t)idle_pool.size() >= IDLE_POOL_MAX)
  {
    // 先取出标识再释放,避免日志读到已 delete 的 buffer(use-after-free)
    // 仅在开启调度日志时使用,普通构建下允许未使用
    [[maybe_unused]] u64_t id = buf->id;
    [[maybe_unused]] u64_t seq = buf->get_seq();
    SCHED_LOG(g_sched_role, "SWEEP_PRE", (long long)id, (long long)seq, "PROCESSED",
              -1, (int)idle_pool.size(), -1);
    releaseBuffer(buf);
    SCHED_LOG(g_sched_role, "SWEEP", (long long)id, (long long)seq, "EMPTY",
              -1, (int)idle_pool.size(), -1);
    return;
  }
  SCHED_LOG(g_sched_role, "EMPTY_PRE", buf->id, (long long)buf->get_seq(), "PROCESSED",
            -1, (int)idle_pool.size(), -1);
  idle_pool.push_back(buf);
  SCHED_LOG(g_sched_role, "EMPTY", buf->id, (long long)buf->get_seq(), "EMPTY",
            -1, (int)idle_pool.size(), -1);
}
