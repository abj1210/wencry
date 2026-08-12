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
  加密/解密/验证三种模式共用同一缓冲池与HASH线程:
    - 加密:  EMPTY --读--> LOADED --AES--> CLAIMED --> PROCESSED --HASH--> HASHED --写--> EMPTY
    - 解密:  EMPTY --读--> LOADED --HASH--> HASHED --AES--> CLAIMED --> PROCESSED --写--> EMPTY
    - 验证:  EMPTY --读--> LOADED --HASH(读完即回收)--> EMPTY
  HASH 线程是严格按块序(0,1,2,...)消费密文的消费者,保证 HMAC 顺序正确;
  在解密中先于 AES(密文会被覆盖),在加密中位于 AES 与写之间(写线程释放缓冲前)。
  工作线程按 thread_seq_tag 的块序逐个排空,收尾统一由哨兵(buffer_id >= size)判定。
  终止:读线程读到 EOF 后置 read_done 并记录 total_chunks;HASH线程消费完所有块后退出;
        写线程写完 total_chunks 个 chunk 后退出;工作线程在无任务(哨兵)后退出。
  同步:单一 mtx + cv_empty/cv_loaded/cv_processed/cv_hash;fread/fwrite 在锁外执行。
  死锁安全:流水线为读->HASH->AES->写单向 DAG,各线程等待的是下游进展,无环。
################################*/

/*################################
  初始化
################################*/

buffergroup *buffergroup::instance = NULL;
std::mutex buffergroup::mtx_singleton;

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

/*
set_thread_tag:为缓冲登记所属线程并分配块序号
buffer_id:缓冲标号
thread_id:所属工作线程
*/
void buffergroup::set_thread_tag(u8_t buffer_id, u8_t thread_id)
{
  thread_id_tag[buffer_id] = thread_id;
  int max_seq = -1;
  for (u32_t i = 0; i < size; i++)
  {
    if (thread_id_tag[i] == thread_id && thread_seq_tag[i] > max_seq)
      max_seq = thread_seq_tag[i];
  }
  thread_seq_tag[buffer_id] = max_seq + 1;
};
/*
remove_thread_tag:块写出后移除归属并递减同线程其余块的序号
buffer_id:缓冲标号
return:序号为0时成功移除返回true
*/
bool buffergroup::remove_thread_tag(u8_t buffer_id)
{
  if (thread_seq_tag[buffer_id] != 0)
    return false;
  for (u32_t i = 0; i < size; i++)
  {
    if (thread_id_tag[i] == thread_id_tag[buffer_id])
      thread_seq_tag[i]--;
  }
  thread_id_tag[buffer_id] = -1;
  return true;
};
/*
judge_buffer_loaded:判断本工作线程当前应"认领"还是"退出"
thread_id:工作线程标号
return:true表示可认领或应退出(assign返回哨兵);false表示继续等待
加密认领 LOADED(AES 直接处理);解密认领 HASHED(等HASH读完密文)。
关键:read_done 后本线程的块可能仍处于 LOADED(等待HASH线程置HASHED),
此时不能返回 true 让 worker 提前退出,否则该块被遗弃导致写线程死锁。
*/
bool buffergroup::judge_buffer_loaded(u8_t thread_id)
{
  bufstate_t ready = (mode == PIPE_ENCRYPT) ? LOADED : HASHED;
  bool has_ready = false, has_pending = false;
  for (u32_t i = 0; i < size; i++)
  {
    if (thread_id_tag[i] != (int)thread_id)
      continue;
    if (state[i] == ready)
      has_ready = true;
    if (state[i] == LOADED)
      has_pending = true; // 解密:密文待哈希;加密:ready==LOADED已计入
  }
  if (has_ready)
    return true;
  if (read_done && !has_pending)
    return true; // 读结束且本线程无待处理块 → 退出
  return false;
};
/*
assign_buffer_id:为本工作线程领取序号最小的可认领缓冲并置为CLAIMED
thread_id:工作线程标号
return:缓冲标号;无可用缓冲返回0xFF(哨兵)
*/
u8_t buffergroup::assign_buffer_id(u8_t thread_id)
{
  int min_seq = 0x7fffffff;
  u8_t buffer_id = 0xFF;
  bufstate_t ready = (mode == PIPE_ENCRYPT) ? LOADED : HASHED;
  for (u32_t i = 0; i < size; i++)
  {
    if (thread_id_tag[i] == thread_id && state[i] == ready && thread_seq_tag[i] < min_seq)
    {
      min_seq = thread_seq_tag[i];
      buffer_id = (u8_t)i;
    }
  }
  if (buffer_id < size)
    state[buffer_id] = CLAIMED;
  return buffer_id;
};
/*
judge_buffer_full:判断写线程当前块是否可写出
next:当前块号
thread_id:当前块所属线程
buffer_id:当前块所在缓冲
return:可写出返回true
加密等 HASHED(HASH读完密文);解密等 PROCESSED(AES完成)
*/
bool buffergroup::judge_buffer_full(u8_t next, u8_t thread_id, u8_t buffer_id)
{
  if (read_done && next == total_chunks)
    return true;
  bufstate_t ready = (mode == PIPE_ENCRYPT) ? HASHED : PROCESSED;
  if (state[buffer_id] == ready && thread_seq_tag[buffer_id] == 0 && thread_id_tag[buffer_id] == thread_id)
    return true;
  return false;
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
del_instance:删除实例
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
size:缓冲个数(工作线程数+冗余)
total_threads:工作线程数
fin:输入文件
fout:输出文件(验证模式可为NULL)
mode:流水线模式(加密/解密/验证)
return:实际缓冲个数
*/
u8_t buffergroup::set_buffergroup(u32_t size, u32_t total_threads, FILE *fin, FILE *fout, pipe_mode mode)
{
  this->size = size <= MAX_BUF ? size : MAX_BUF;
  this->total_threads = total_threads;
  this->fin = fin;
  this->fout = fout;
  this->mode = mode;
  this->ispadding = (mode == PIPE_ENCRYPT);
  this->buflst = new iobuffer[this->size];
  std::lock_guard<std::mutex> lock(mtx);
  for (u32_t i = 0; i < this->size; ++i)
  {
    state[i] = EMPTY;
    thread_id_tag[i] = -1;
    thread_seq_tag[i] = -1;
  }
  over = false;
  read_done = false;
  total_chunks = 0;
  return this->size;
};

/*################################
  工作线程接口
################################*/

/*
wait_loaded:等待一个属于本线程的可认领缓冲并领取(置CLAIMED)
thread_id:工作线程标号
return:缓冲标号;无任务返回0xFF哨兵
*/
u8_t buffergroup::wait_loaded(const u8_t thread_id)
{
  u8_t buffer_id = 0xFF;
  {
    std::unique_lock<std::mutex> locker(mtx);
    cv_loaded.wait(locker, [&] { return judge_buffer_loaded(thread_id); });
    buffer_id = assign_buffer_id(thread_id);
  }
  return buffer_id;
}

/*
stop_worker:判断工作线程是否应退出
buffer_id:领取到的缓冲标号
return:true表示本线程已无任务,应退出
*/
bool buffergroup::stop_worker(const u8_t buffer_id)
{
  // buffer_id >= size 是 assign_buffer_id 在"本线程已无可认领块"时返回的哨兵(0xFF)。
  return buffer_id >= size;
}
/*
get_entry:获取缓冲区下一个表项
buffer_id:缓冲标号
return:表项地址,若缓冲区已经读取完毕返回NULL
*/
u8_t *buffergroup::get_entry(const u8_t buffer_id)
{
  if (buffer_id >= size)
    return NULL;
  return buflst[buffer_id].get_entry();
}
/*
finish_chunk:标记本块已处理完毕(AES完成)
buffer_id:缓冲标号
return:读线程是否已结束(供外部参考)
*/
bool buffergroup::finish_chunk(const u8_t buffer_id)
{
  if (buffer_id >= size)
    return false;
  bool local_done;
  {
    std::lock_guard<std::mutex> locker(mtx);
    state[buffer_id] = PROCESSED;
    local_done = read_done;
  }
  cv_processed.notify_all();
  cv_hash.notify_all();
  return local_done;
}

/*################################
  读线程
################################*/
/*
run_read:读线程,按顺序装载chunk
printload:过程打印函数
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
  u32_t next = 0;
  while (true)
  {
    u8_t id = (u8_t)(next % size);
    u8_t thread_id = (u8_t)(next % total_threads);
    {
      std::unique_lock<std::mutex> locker(mtx);
      cv_empty.wait(locker, [&] { return state[id] == EMPTY || over; });
      if (over)
        break;
    }
    PROF_LOG("LOAD_BEGIN", next);
    loadstate_t ls = buflst[id].load_buffer(fin, ispadding);
    PROF_LOG("LOAD_END", next);
    {
      std::lock_guard<std::mutex> locker(mtx);
      if (ls == FULL)
      {
        state[id] = LOADED;
        ++next;
      }
      else
      {
        // FINAL:最后一个数据块(含填充); NODATA:无数据
        if (ls == FINAL)
        {
          state[id] = LOADED;
          ++next;
        }
        over = true;
        total_chunks = next;
        read_done = true;
      }
      set_thread_tag(id, thread_id);
      cv_loaded.notify_all();
      cv_hash.notify_all();
      if (over)
        break;
    }
  }
}

/*################################
  HASH线程
################################*/
/*
run_hash:HASH线程,按块序号顺序消费密文并喂入HMAC
printload:过程打印函数
加密读 AES 后的 PROCESSED 密文;解密/验证读 LOADED 密文(先于AES覆盖)。
验证模式读完即回收(置EMPTY),加密/解密置HASHED交给下一级。
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
  u32_t next = 0;
  bufstate_t target = (mode == PIPE_ENCRYPT) ? PROCESSED : LOADED;
  while (true)
  {
    u8_t id = (u8_t)(next % size);
    {
      std::unique_lock<std::mutex> locker(mtx);
      cv_hash.wait(locker, [&] { return state[id] == target || (read_done && next == total_chunks); });
      if (read_done && next == total_chunks)
        break;
    }
    if (hash_feed)
      hash_feed(buflst[id].get_data(), buflst[id].data_len());
    {
      std::lock_guard<std::mutex> locker(mtx);
      if (mode == PIPE_VERIFY)
        state[id] = EMPTY; // 验证读完即回收
      else
        state[id] = HASHED;
      ++next;
      cv_loaded.notify_all();
      cv_processed.notify_all();
      cv_empty.notify_all();
    }
  }
}

/*################################
  写线程
################################*/
/*
run_write:写线程,按chunk序号顺序导出
printload:过程打印函数
加密等 HASHED(哈希线程已读密文);解密等 PROCESSED(AES完成)。
*/
void buffergroup::run_write(const std::function<void(std::string, size_t)> &printload)
{
#ifdef _WIN32
  SetThreadDescription(GetCurrentThread(), L"WriteThread");
#endif
#ifdef PROFILE_THREADS
  g_thread_role = "write";
#endif
  u32_t next = 0;
  while (true)
  {
    u8_t id = (u8_t)(next % size);
    u8_t thread_id = (u8_t)(next % total_threads);
    {
      std::unique_lock<std::mutex> locker(mtx);
      cv_processed.wait(locker, [&] { return judge_buffer_full(next, thread_id, id); });
      if (read_done && next == total_chunks)
        break;
    }
    PROF_LOG("WRITE_BEGIN", next);
    u32_t n = buflst[id].export_buffer(fout, ispadding);
    PROF_LOG("WRITE_END", next);
    printload("Chunk " + std::to_string(next), n);
    {
      std::lock_guard<std::mutex> locker(mtx);
      remove_thread_tag(id);
      state[id] = EMPTY;
      ++next;
      cv_empty.notify_all();
    }
  }
}
