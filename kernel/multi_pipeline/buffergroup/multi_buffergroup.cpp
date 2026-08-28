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
  内存回收:读取完成后,写线程不再归还空闲池而直接释放并清空空闲池,内存随流水线结束收敛;del_instance 兜底释放。
  死锁安全:流水线为读->工作->写单向 DAG,各线程等待的是下游进展,无环。
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
      SCHED_LOG("?", "RUN_END", -1, -1, "", 0, 0, 0);
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
    release_buffer(kv.second);
  work_pool.clear();
  while (!processed_pool.empty())
  {
    release_buffer(processed_pool.top());
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
has_claimable_locked:工作池中是否有特定序号的缓冲
seq_next:指定的序号
return:若有，返回true
*/
bool buffergroup::has_claimable_locked(const u64_t seq_next) const
{
  return work_pool.find(seq_next) != work_pool.end();
}
/*
claim_locked:领取工作线程中特定序号的缓冲
thread_id:工作线程标号
return:领取到的 buffer;无则返回 NULL(退出哨兵)
*/
iobuffer *buffergroup::claim_locked(const u64_t seq_next)
{
  auto kv = work_pool.find(seq_next);
  if(kv == work_pool.end()) 
    return NULL;
  else
    return kv->second;
}
/*
worker_pending_locked:本线程是否仍有未处理完的块
thread_id:工作线程标号
return:若有，返回true
*/
bool buffergroup::worker_pending_locked(const u8_t thread_id) const
{
  for (auto &kv : work_pool)
  {
    iobuffer *b = kv.second;
    if (b->seq % total_threads == thread_id)
      return true;
  }
  return false;
}

/*
chunk_ready_locked:指定序号的块是否位于已处理池的堆顶(用于同步写入顺序)
seq:块序号
return:该块存在返回 true
*/
bool buffergroup::chunk_ready_locked(const u64_t seq) const
{
  if(processed_pool.empty())
    return false;
  iobuffer * buf = processed_pool.top();
  return buf->seq == seq;
}
/*
claim_processed:领取已处理池中的堆顶缓冲
return:堆顶缓冲
*/
iobuffer *buffergroup::claim_processed(){
  if(processed_pool.empty())
    return NULL;
  return processed_pool.top();
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
    release_buffer(buf);
    sweep_idle_locked();
    return;
  }
  u64_t now = steady_us();
  while (!idle_pool.empty() && (now - idle_pool.front()->idle_ts) > (u64_t)IDLE_TIMEOUT_MS * 1000ULL)
  {
    if(idle_pool.front()->claimed)
      break;
    release_buffer(idle_pool.front());
    idle_pool.pop_front();
  }
  if ((u32_t)idle_pool.size() >= IDLE_POOL_MAX)
  {
    release_buffer(buf);
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
sweep_idle_locked:清空空闲池(释放全部空 buffer)
*/
void buffergroup::sweep_idle_locked()
{
  if (!idle_pool.empty())
  {
    SCHED_LOG(g_sched_role, "SWEEP_PRE", -1, -1, "", (int)work_pool.size(), (int)idle_pool.size(), (int)processed_pool.size());
    for (auto *b : idle_pool)
      release_buffer(b);
    idle_pool.clear();
    SCHED_LOG(g_sched_role, "SWEEP", -1, -1, "", (int)work_pool.size(), (int)idle_pool.size(), (int)processed_pool.size());
  }
}

/*
release_buffer:释放一个 buffer,记录释放前后的内存追踪事件
buf:待释放 buffer
*/
void buffergroup::release_buffer(iobuffer *buf)
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
wait_loaded:等待一个属于本线程的可领取块并领取
thread_id:工作线程标号
next:期望领取的缓冲区序号
return:领取到的 buffer;无任务返回 NULL 哨兵
*/
iobuffer *buffergroup::wait_loaded_buffer(const u8_t thread_id, const u64_t next)
{
  std::unique_lock<std::mutex> locker(mtx);
  cv.wait(locker, [&] {
    return (has_claimable_locked(next) || (read_done && !worker_pending_locked(thread_id)));
  });
  return claim_locked(next);
}

/*
finish_processing:工作线程将处理完成的缓冲区从工作池移动到已处理池，并返回下一个期望的缓冲序号
buffer:处理完成的缓冲
return:下一个期望的缓冲序号
先将缓冲从工作池中移除，并将其加入已处理池进行排序。
*/
u64_t buffergroup::finish_processing(iobuffer *buffer)
{
  std::unique_lock<std::mutex> locker(mtx);
  SCHED_LOG(g_sched_role, "POP_WORK_PRE", buffer->id, buffer->seq, "CLAIMED",
            (int)work_pool.size(), (int)idle_pool.size(), (int)processed_pool.size());
  work_pool.erase(buffer->seq);
  SCHED_LOG(g_sched_role, "POP_WORK", buffer->id, buffer->seq, "POP_WORK",
              (int)work_pool.size(), (int)idle_pool.size(), (int)processed_pool.size());
  SCHED_LOG(g_sched_role, "PROCESSED_PRE", buffer->id, buffer->seq, "PROCESSING",
            (int)work_pool.size(), (int)idle_pool.size(), (int)processed_pool.size());
  processed_pool.push(buffer);
  SCHED_LOG(g_sched_role, "PROCESSED", buffer->id, buffer->seq, "PROCESSED",
            (int)work_pool.size(), (int)idle_pool.size(), (int)processed_pool.size());
  u64_t next = buffer->seq + total_threads;
  cv.notify_all();
  return next; 
}

/*
wait_cleared_buffer:读线程获取一个空闲 buffer(空闲池空则动态 new)
return:空闲 buffer
*/
iobuffer *buffergroup::wait_cleared_buffer(){
  std::unique_lock<std::mutex> locker(mtx);
  if(read_done)
    return NULL;
  iobuffer *buf;
  if (idle_pool.empty()){
    SCHED_LOG(g_sched_role, "BUF_NEW_PRE", -1, -1, "",
              (int)work_pool.size(), (int)idle_pool.size(), (int)processed_pool.size());
    buf = new iobuffer;
    idle_pool.push_back(buf); // 新分配的 buffer 也计入空闲池
  }else{
    buf = idle_pool.front();
  }
  buf->claimed = true; // 认领后仍留在空闲池中
  SCHED_LOG(g_sched_role, "POP_IDLE_PRE", buf->id, buf->seq, "EMPTY",
            (int)work_pool.size(), (int)idle_pool.size(), (int)processed_pool.size());
  return buf;
}

/*
finish_loading:读线程装入完成后把 buffer 注册进工作池
buffer:刚装入的 buffer
ls:装载状态(FULL/FINAL/NODATA)
next:本块全局序号
return:true 表示已读到末尾(FINAL/NODATA),读线程应退出;false 继续读
FULL:置 LOADED 入工作池;FINAL:入工作池并记录 total_chunks = next+1;
NODATA:空 buffer 直接释放,total_chunks = next。
总在途块数(work_pool + processed_pool)达到 WORK_PROCESSED_MAX 时阻塞,实现有界背压。
*/
bool buffergroup::finish_loading(iobuffer *buffer, const loadstate_t ls, const u64_t next){
  std::unique_lock<std::mutex> locker(mtx);
  cv.wait(locker, [&] {
    return (work_pool.size() + processed_pool.size()) < WORK_PROCESSED_MAX;
  });
  // 从空闲池取出被认领的 buffer
  if (!idle_pool.empty() && idle_pool.front() == buffer)
    idle_pool.pop_front();
  buffer->claimed = false;
  SCHED_LOG(g_sched_role, "POP_IDLE", buffer->id, buffer->seq, "EMPTY",
            (int)work_pool.size(), (int)idle_pool.size(), (int)processed_pool.size());
  if (ls == FULL)
  {
    buffer->seq = next;
    SCHED_LOG(g_sched_role, "LOADED_PRE", buffer->id, buffer->seq, "LOADING",
              (int)work_pool.size(), (int)idle_pool.size(), (int)processed_pool.size());
    work_pool[next] = buffer;
    SCHED_LOG(g_sched_role, "LOADED", buffer->id, buffer->seq, "LOADED",
              (int)work_pool.size(), (int)idle_pool.size(), (int)processed_pool.size());
    cv.notify_all();
    return false;
  }
  else
  {
    // FINAL:最后一个数据块(含填充); NODATA:无数据
    if (ls == FINAL)
    {
      buffer->seq = next;
      SCHED_LOG(g_sched_role, "LOADED_PRE", buffer->id, buffer->seq, "LOADING",
                (int)work_pool.size(), (int)idle_pool.size(), (int)processed_pool.size());
      work_pool[next] = buffer;
      total_chunks = next + 1; // 已装入块号为 next,块总数 = next + 1
      SCHED_LOG(g_sched_role, "LOADED", buffer->id, buffer->seq, "LOADED",
                (int)work_pool.size(), (int)idle_pool.size(), (int)processed_pool.size());
    }
    else
    {
      release_buffer(buffer); // NODATA:空缓冲直接释放
      total_chunks = next; // 未装入新块,块总数 = next
    }
    read_done = true;
    SCHED_LOG(g_sched_role, "READ_DONE", -1, (long long)next, "", (int)work_pool.size(), (int)idle_pool.size(), (int)processed_pool.size());
    cv.notify_all();
    return true;
  }
}

/*
wait_processed_buffer:写线程等待指定序号的块进入可写状态
next:块序号
return:该块 buffer;读取完成且无更多块返回 NULL(退出哨兵)
*/
iobuffer *buffergroup::wait_processed_buffer(const u64_t next){
  std::unique_lock<std::mutex> locker(mtx);
  cv.wait(locker, [&] { return chunk_ready_locked(next) || (read_done && next == total_chunks); });
  if (read_done && next == total_chunks)
  {
    sweep_idle_locked(); // 兜底:读取完成后清空空闲池
    return NULL;
  }
  return claim_processed();
}

/*
finish_clearing:写线程写出一个块后,从工作池移除并回收
buffer:已写出的块
*/
void buffergroup::finish_clearing(iobuffer *buffer){
  std::unique_lock<std::mutex> locker(mtx);
  SCHED_LOG(g_sched_role, "POP_PROCESSED_PRE", buffer->id, buffer->seq, "PROCESSED",
            (int)work_pool.size(), (int)idle_pool.size(), (int)processed_pool.size());
  processed_pool.pop();
  SCHED_LOG(g_sched_role, "POP_PROCESSED", buffer->id, buffer->seq, "PROCESSED",
            (int)work_pool.size(), (int)idle_pool.size(), (int)processed_pool.size());
  recycle_locked(buffer);
  cv.notify_all();
}
