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
  单缓冲区函数
################################*/
/*
load_buffer:更新缓冲区
fin:输入文件
ispadding:是否填充
return:返回装载状态
*/
loadstate_t iobuffer::load_buffer(FILE *fin, bool ispadding)
{
  u32_t load = fread(b, 1, sum, fin);
  bool readover = feof(fin);
  if (!ispadding && !readover && load == sum)
  {
    int c = fgetc(fin);
    readover = (c == EOF);
    if (!readover)
      fseek(fin, -1, SEEK_CUR);
  }
  tail = load & 0xf;
  total = load >> 4;
  now = 0;
  if (ispadding && (load != sum))
  {
    u8_t padding = 16 - tail;
    memset(b[total++] + tail, padding, padding);
    isfinal = true;
    return FINAL;
  }
  if ((!ispadding) && readover)
  {
    if (load == 0)
      return NODATA;
    isfinal = true;
    return FINAL;
  }
  return load == 0 ? NODATA : FULL;
}
/*
export_buffer:将缓冲区内容保存到文件
fout:输出文件
ispadding:是否填充
return:写出的字节数
*/
u32_t iobuffer::export_buffer(FILE *fout, bool ispadding)
{
  if (now == 0)
    return 0;
  if (isfinal)
  {
    u8_t padding = ispadding ? 0 : b[now - 1][15];
    if (padding > (now << 4))
      padding = (u8_t)(now << 4);
    u32_t n = (now << 4) - padding;
    fwrite(b, 1, n, fout);
    return n;
  }
  fwrite(b, 1, sum, fout);
  return sum;
}

/*################################
  缓冲组管理
################################*/

buffergroup *buffergroup::instance = NULL;
std::mutex buffergroup::mtx_singleton;

/*
steady_us:steady_clock 微秒时间戳(用于空闲池超时判定)
*/
u64_t buffergroup::steady_us()
{
  return (u64_t)std::chrono::duration_cast<std::chrono::microseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

/*
get_instance:获取实例
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
void buffergroup::set_buffergroup(u32_t total_threads, FILE *fin, FILE *fout, pipe_mode mode)
{
  std::lock_guard<std::mutex> lock(mtx);
  this->total_threads = total_threads;
  this->fin = fin;
  this->fout = fout;
  this->mode = mode;
  this->ispadding = (mode == PIPE_ENCRYPT);
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
get_entry:获取缓冲区下一个表项
buffer:缓冲
return:表项地址,若缓冲区已经读取完毕返回NULL
*/
u8_t *buffergroup::get_entry(iobuffer *buffer)
{
  if (buffer == NULL)
    return NULL;
  return buffer->get_entry();
}
/*
finish_chunk:标记本块已处理完毕(AES完成)
buffer:缓冲
*/
void buffergroup::finish_chunk(iobuffer *buffer)
{
  if (buffer == NULL)
    return;
  {
    std::lock_guard<std::mutex> locker(mtx);
    buffer->state = PROCESSED;
  }
  cv.notify_all();
}

/*################################
  读线程
################################*/
/*
run_read:读线程,按序装载chunk并分配全局序号
printload:过程打印函数
工作池满则阻塞(背压);空闲池空则动态 new 一个 buffer。
*/
void buffergroup::run_read(const std::function<void(std::string, size_t)> &printload)
{
  (void)printload;
#ifdef _WIN32
  SetThreadDescription(GetCurrentThread(), L"ReadThread");
#endif
#ifdef PROFILE_THREADS
  g_thread_role = "read";
#endif
  u64_t next = 0;
  while (true)
  {
    iobuffer *buf;
    {
      std::unique_lock<std::mutex> locker(mtx);
      cv.wait(locker, [&] { return work_pool.size() < WORK_POOL_MAX; });
      if (idle_pool.empty())
        buf = new iobuffer;
      else
      {
        buf = idle_pool.front();
        idle_pool.pop_front();
      }
    }
    PROF_LOG("LOAD_BEGIN", next);
    loadstate_t ls = buf->load_buffer(fin, ispadding);
    PROF_LOG("LOAD_END", next);
    {
      std::lock_guard<std::mutex> locker(mtx);
      if (ls == FULL)
      {
        buf->seq = next;
        buf->state = LOADED;
        work_pool[next++] = buf;
        cv.notify_all();
      }
      else
      {
        // FINAL:最后一个数据块(含填充); NODATA:无数据
        if (ls == FINAL)
        {
          buf->seq = next;
          buf->state = LOADED;
          work_pool[next++] = buf;
        }
        else
        {
          delete buf; // NODATA:空缓冲直接释放
        }
        total_chunks = next;
        read_done = true;
        cv.notify_all();
        break;
      }
    }
  }
}

/*################################
  HASH线程
################################*/
/*
run_hash:HASH线程,按全局序号顺序消费密文并喂入HMAC
printload:过程打印函数
加密读 AES 后的 PROCESSED 密文;解密/验证读 LOADED 密文(先于AES覆盖)。
验证模式读完即回收(回收逻辑由 recycle_locked 处理);加密/解密置 HASHED 交给下一级。
*/
void buffergroup::run_hash(const std::function<void(std::string, size_t)> &printload)
{
  (void)printload;
#ifdef _WIN32
  SetThreadDescription(GetCurrentThread(), L"HashThread");
#endif
#ifdef PROFILE_THREADS
  g_thread_role = "hash";
#endif
  u64_t next = 0;
  bufstate_t target = (mode == PIPE_ENCRYPT) ? PROCESSED : LOADED;
  while (true)
  {
    iobuffer *buf;
    {
      std::unique_lock<std::mutex> locker(mtx);
      cv.wait(locker, [&] { return chunk_ready_locked(next, target) || (read_done && next == total_chunks); });
      if (read_done && next == total_chunks)
      {
        sweep_idle_locked(); // 读取已完成,清理空闲池残留(验证模式无写线程,由此兜底)
        break;
      }
      buf = work_pool[next];
    }
    if (hash_feed)
      hash_feed(buf->get_data(), buf->data_len());
    {
      std::lock_guard<std::mutex> locker(mtx);
      if (mode == PIPE_VERIFY)
      {
        work_pool.erase(next);
        recycle_locked(buf); // 验证读完即回收
      }
      else
      {
        buf->state = HASHED;
      }
      ++next;
      cv.notify_all();
    }
  }
}

/*################################
  写线程
################################*/
/*
run_write:写线程,按全局序号顺序导出
printload:过程打印函数
加密等 HASHED(哈希线程已读密文);解密等 PROCESSED(AES完成)。
写出后回收 buffer:读取完成后直接释放并清空空闲池,否则归还空闲池(满/超时则释放)。
*/
void buffergroup::run_write(const std::function<void(std::string, size_t)> &printload)
{
#ifdef _WIN32
  SetThreadDescription(GetCurrentThread(), L"WriteThread");
#endif
#ifdef PROFILE_THREADS
  g_thread_role = "write";
#endif
  u64_t next = 0;
  bufstate_t ready = (mode == PIPE_ENCRYPT) ? HASHED : PROCESSED;
  while (true)
  {
    iobuffer *buf;
    {
      std::unique_lock<std::mutex> locker(mtx);
      cv.wait(locker, [&] { return chunk_ready_locked(next, ready) || (read_done && next == total_chunks); });
      if (read_done && next == total_chunks)
      {
        sweep_idle_locked(); // 兜底:读取完成后清空空闲池
        break;
      }
      buf = work_pool[next];
    }
    PROF_LOG("WRITE_BEGIN", next);
    u32_t n = buf->export_buffer(fout, ispadding);
    PROF_LOG("WRITE_END", next);
    printload("Chunk " + std::to_string(next), n);
    {
      std::lock_guard<std::mutex> locker(mtx);
      work_pool.erase(next);
      recycle_locked(buf);
      ++next;
      cv.notify_all();
    }
  }
}
