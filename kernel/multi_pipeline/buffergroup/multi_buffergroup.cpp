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
    读线程从空闲池认领 buffer(空则 new,认领后仍留在空闲池中),fread 装满后移入工作池;
    工作线程按 seq%total_threads 路由领取最小 seq 的块,AES/HMAC 完成后移入已处理池;
    写线程按 seq 递增从已处理池取出写出,并回收 buffer 到空闲池(空闲池满/超时则释放)。
  统一序号 seq 取代原 threadid/seq 双标志:序号既决定顺序,又通过 seq%total_threads 推导归属线程。
  终止:读线程读到 EOF 后置 read_done 并记录 total_chunks;工作线程无任务后退出;
        写线程写完 total_chunks 个 chunk 后退出。
  同步:单一 mtx + 单一 cv(所有状态变更 notify_all,等待方用谓词自旋);fread/fwrite 在锁外执行。
  背压:工作池+已处理池总在途块数达到 WORK_PROCESSED_MAX 时读线程阻塞。
  内存回收:读取完成后,写线程不再归还空闲池而直接释放并清空空闲池,内存随流水线结束收敛;delInstance 兜底释放。
  死锁安全:流水线为读->工作->写单向 DAG,各线程等待的是下游进展,无环。
################################*/



/*################################
  缓冲组管理
################################*/

BufferGroup *BufferGroup::instance = NULL;
std::mutex BufferGroup::mtx_singleton;

/*
steadyUs:steady_clock 微秒时间戳(用于空闲池超时判定)
return:自进程启动以来的微秒数
*/
u64_t BufferGroup::steadyUs()
{
  return (u64_t)std::chrono::duration_cast<std::chrono::microseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

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
setBufferGroup:设置缓冲区组选项与流水线模式
total_threads:工作线程数
fin:输入文件
fout:输出文件(验证模式可为NULL)
mode:流水线模式(加密/解密/验证)
*/
void BufferGroup::setBufferGroup(u32_t total_threads, pipe_mode mode)
{
  std::lock_guard<std::mutex> lock(mtx);
  this->total_threads = total_threads;
  this->mode = mode;
  this->total_chunks = 0;
  this->read_done = false;
  sweepIdlePool();
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

/*################################
  加锁辅助函数(均要求持有 mtx)
################################*/

/*
acquireIdleBuffer:从空闲池取一个空 buffer(空则 new),标记 claimed 后返回
return:待装载的空 buffer
*/
IoBuffer *BufferGroup::acquireIdleBuffer()
{
  IoBuffer *buf;
  if (idle_pool.empty())
  {
    SCHED_LOG(g_sched_role, "BUF_NEW_PRE", -1, -1, "",
              (int)work_pool.size(), (int)idle_pool.size(), (int)processed_pool.size());
    buf = new IoBuffer;
    idle_pool.push_back(buf); // 新分配的 buffer 也计入空闲池
  }
  else
  {
    buf = idle_pool.front();
  }
  buf->claimed = true; // 认领后仍留在空闲池中
  SCHED_LOG(g_sched_role, "POP_IDLE_PRE", buf->id, buf->seq, "EMPTY",
            (int)work_pool.size(), (int)idle_pool.size(), (int)processed_pool.size());
  return buf;
}

/*
registerLoadedChunk:把已装载的 buffer 注册进工作池(LOADED)
buf:刚装载完成的 buffer
next:本块全局序号
*/
void BufferGroup::registerLoadedChunk(IoBuffer *buf, const u64_t next)
{
  buf->seq = next;
  SCHED_LOG(g_sched_role, "LOADED_PRE", buf->id, buf->seq, "LOADING",
            (int)work_pool.size(), (int)idle_pool.size(), (int)processed_pool.size());
  work_pool[next] = buf;
  SCHED_LOG(g_sched_role, "LOADED", buf->id, buf->seq, "LOADED",
            (int)work_pool.size(), (int)idle_pool.size(), (int)processed_pool.size());
}

/*
workerHasPendingChunk:判断本线程名下是否仍有未处理的 LOADED 块
thread_id:工作线程标号
return:有则返回 true
*/
bool BufferGroup::workerHasPendingChunk(const u8_t thread_id) const
{
  for (auto &kv : work_pool)
  {
    if (kv.second->seq % total_threads == thread_id)
      return true;
  }
  return false;
}

/*
loadedChunkReady:本线程是否可领取 next 块(该块已入工作池,或读结束且本线程无剩余块)
next:块序号;thread_id:工作线程标号
*/
bool BufferGroup::loadedChunkReady(const u64_t next, const u8_t thread_id) const
{
  return (work_pool.find(next) != work_pool.end()) ||
         (read_done && !workerHasPendingChunk(thread_id));
}

/*
hasInFlightCapacity:工作池与已处理池的在途块数是否低于上限(读线程背压)
*/
bool BufferGroup::hasInFlightCapacity() const
{
  return (work_pool.size() + processed_pool.size()) < WORK_PROCESSED_MAX;
}

/*
processedChunkReady:待写块 next 是否就绪(已位于已处理池堆顶,或读结束且无更多块)
next:块序号
*/
bool BufferGroup::processedChunkReady(const u64_t next) const
{
  return (!processed_pool.empty() && processed_pool.top()->seq == next) ||
         (read_done && next == total_chunks);
}

/*
promoteToProcessed:工作线程处理完成后,把 buffer 从工作池移到已处理池
buf:刚处理完成的 buffer
*/
void BufferGroup::promoteToProcessed(IoBuffer *buf)
{
  SCHED_LOG(g_sched_role, "POP_WORK_PRE", buf->id, buf->seq, "CLAIMED",
            (int)work_pool.size(), (int)idle_pool.size(), (int)processed_pool.size());
  work_pool.erase(buf->seq);
  SCHED_LOG(g_sched_role, "POP_WORK", buf->id, buf->seq, "POP_WORK",
            (int)work_pool.size(), (int)idle_pool.size(), (int)processed_pool.size());
  SCHED_LOG(g_sched_role, "PROCESSED_PRE", buf->id, buf->seq, "PROCESSING",
            (int)work_pool.size(), (int)idle_pool.size(), (int)processed_pool.size());
  processed_pool.push(buf);
  SCHED_LOG(g_sched_role, "PROCESSED", buf->id, buf->seq, "PROCESSED",
            (int)work_pool.size(), (int)idle_pool.size(), (int)processed_pool.size());
}

/*
popProcessed:写线程写出后,把 buffer 从已处理池移除
buf:已写出的 buffer
*/
void BufferGroup::popProcessed(IoBuffer *buf)
{
  SCHED_LOG(g_sched_role, "POP_PROCESSED_PRE", buf->id, buf->seq, "PROCESSED",
            (int)work_pool.size(), (int)idle_pool.size(), (int)processed_pool.size());
  processed_pool.pop();
  SCHED_LOG(g_sched_role, "POP_PROCESSED", buf->id, buf->seq, "PROCESSED",
            (int)work_pool.size(), (int)idle_pool.size(), (int)processed_pool.size());
}

/*
recycleClearedBuffer:回收已写出的 buffer
buf:待回收 buffer
读取完成后(read_done)不再复用,直接释放并清空空闲池;
读取进行中则淘汰空闲超时的 buffer,空闲池满则释放本 buffer,否则置 EMPTY 归还空闲池。
*/
void BufferGroup::recycleClearedBuffer(IoBuffer *buf)
{
  if (read_done)
  {
    releaseBuffer(buf);
    sweepIdlePool();
    return;
  }
  u64_t now = steadyUs();
  while (!idle_pool.empty() && (now - idle_pool.front()->idle_ts) > (u64_t)IDLE_TIMEOUT_MS * 1000ULL)
  {
    if(idle_pool.front()->claimed)
      break;
    releaseBuffer(idle_pool.front());
    idle_pool.pop_front();
  }
  if ((u32_t)idle_pool.size() >= IDLE_POOL_MAX)
  {
    releaseBuffer(buf);
    return;
  }
  SCHED_LOG(g_sched_role, "EMPTY_PRE", buf->id, buf->seq, "PROCESSED",
            (int)work_pool.size(), (int)idle_pool.size(), (int)processed_pool.size());
  buf->idle_ts = now;
  idle_pool.push_back(buf);
  SCHED_LOG(g_sched_role, "EMPTY", buf->id, buf->seq, "EMPTY",
            (int)work_pool.size(), (int)idle_pool.size(), (int)processed_pool.size());
}

/*
sweepIdlePool:清空空闲池(释放全部空 buffer)
*/
void BufferGroup::sweepIdlePool()
{
  if (!idle_pool.empty())
  {
    SCHED_LOG(g_sched_role, "SWEEP_PRE", -1, -1, "", (int)work_pool.size(), (int)idle_pool.size(), (int)processed_pool.size());
    for (auto *b : idle_pool)
      releaseBuffer(b);
    idle_pool.clear();
    SCHED_LOG(g_sched_role, "SWEEP", -1, -1, "", (int)work_pool.size(), (int)idle_pool.size(), (int)processed_pool.size());
  }
}

/*
releaseBuffer:释放一个 buffer,记录释放前后的内存追踪事件
buf:待释放 buffer
*/
void BufferGroup::releaseBuffer(IoBuffer *buf)
{
  u64_t id = buf->id;
  u64_t seq = buf->seq;
  delete buf;  // 触发析构,记录 BUF_DELETE(释放前)
  SCHED_LOG(g_sched_role, "BUF_DELETE_AFTER", (long long)id, (long long)seq, "",
            (int)work_pool.size(), (int)idle_pool.size(), (int)processed_pool.size());
}

/*################################
  工作线程接口
################################*/
/*
waitLoadedBuffer:等待一个属于本线程的可领取块并领取
thread_id:工作线程标号
next:期望领取的缓冲区序号
return:领取到的 buffer;无任务返回 NULL 哨兵
*/
IoBuffer *BufferGroup::waitLoadedBuffer(const u8_t thread_id, const u64_t next)
{
  std::unique_lock<std::mutex> locker(mtx);
  cv.wait(locker, [&] { return loadedChunkReady(next, thread_id); });
  auto kv = work_pool.find(next);
  return kv == work_pool.end() ? NULL : kv->second;
}

/*
finishProcessing:工作线程将处理完成的缓冲区从工作池移动到已处理池,并返回下一个期望序号
buffer:处理完成的缓冲
return:下一个期望的缓冲序号
*/
u64_t BufferGroup::finishProcessing(IoBuffer *buffer)
{
  std::unique_lock<std::mutex> locker(mtx);
  promoteToProcessed(buffer);
  u64_t next = buffer->seq + total_threads;
  cv.notify_all();
  return next;
}

/*
waitClearedBuffer:读线程获取一个空闲 buffer
return:空闲 buffer(读取结束后返回 NULL)
*/
IoBuffer *BufferGroup::waitClearedBuffer()
{
  std::unique_lock<std::mutex> locker(mtx);
  if (read_done)
    return NULL;
  return acquireIdleBuffer();
}

/*
finishLoading:读线程装入完成后把 buffer 注册进工作池
buffer:刚装入的 buffer
ls:装载状态(FULL/FINAL/NODATA)
next:本块全局序号
return:true 表示已读到末尾(FINAL/NODATA),读线程应退出;false 继续读
*/
bool BufferGroup::finishLoading(IoBuffer *buffer, const loadstate_t ls, const u64_t next)
{
  std::unique_lock<std::mutex> locker(mtx);
  cv.wait(locker, [&] { return hasInFlightCapacity(); });
  if (!idle_pool.empty() && idle_pool.front() == buffer)
    idle_pool.pop_front();
  buffer->claimed = false;
  SCHED_LOG(g_sched_role, "POP_IDLE", buffer->id, buffer->seq, "EMPTY",
            (int)work_pool.size(), (int)idle_pool.size(), (int)processed_pool.size());
  if (ls == FULL)
  {
    registerLoadedChunk(buffer, next);
    cv.notify_all();
    return false;
  }
  if (ls == FINAL)
  {
    registerLoadedChunk(buffer, next);
    total_chunks = next + 1;
  }
  else
  {
    releaseBuffer(buffer);
    total_chunks = next;
  }
  read_done = true;
  SCHED_LOG(g_sched_role, "READ_DONE", -1, (long long)next, "",
            (int)work_pool.size(), (int)idle_pool.size(), (int)processed_pool.size());
  cv.notify_all();
  return true;
}

/*
waitProcessedBuffer:写线程等待指定序号的块进入可写状态
next:块序号
return:该块 buffer;读取完成且无更多块返回 NULL(退出哨兵)
*/
IoBuffer *BufferGroup::waitProcessedBuffer(const u64_t next)
{
  std::unique_lock<std::mutex> locker(mtx);
  cv.wait(locker, [&] { return processedChunkReady(next); });
  if (read_done && next == total_chunks)
  {
    sweepIdlePool();
    return NULL;
  }
  return processed_pool.top();
}

/*
finishClearing:写线程写出一个块后,从已处理池移除并回收
buffer:已写出的块
*/
void BufferGroup::finishClearing(IoBuffer *buffer)
{
  std::unique_lock<std::mutex> locker(mtx);
  popProcessed(buffer);
  recycleClearedBuffer(buffer);
  cv.notify_all();
}
