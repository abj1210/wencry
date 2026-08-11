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
  模块概述:读线程--工作线程--写线程三级流水线
  本文件实现文件加解密的多线程数据管道。对每个 chunk(一次装载,最大16MB):
    EMPTY --(读线程 fread)--> LOADED --(工作线程就地AES)--> PROCESSED --(写线程 fwrite)--> EMPTY
  线程划分:
    - 读线程(main):按 chunk 序号 k=0,1,2,... 依次装载到 buf[k%N](N=缓冲数),背压等待该缓冲为 EMPTY。
    - 工作线程 i:仅消费 buf[i],对其中每个16字节块执行 AES(其 Aesmode 维护独立的 IV 链)。
    - 写线程:按 chunk 序号顺序导出(PROCESSED->EMPTY),保证输出顺序 == 文件顺序。
  chunk k 固定由线程 k%N 处理,保证该线程 AES 的 IV 链连续(链式模式正确性)。
  终止:读线程读到 EOF(FINAL/NODATA)时置 read_done 并记录 total_chunks;
        写线程写完 total_chunks 个 chunk 后退出;工作线程在 read_done 后退出。
  同步:单一 mtx + cv_empty/cv_loaded/cv_processed;fread/fwrite 在锁外执行以允许 I/O 重叠。
  死锁安全:流水线为读->worker->写单向 DAG,各线程等待的是下游进展,无环。
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
set_buffergroup:设置缓冲区组选项
*/
void buffergroup::set_buffergroup(u32_t size, FILE *fin, FILE *fout, bool ispadding)
{
  this->size = size;
  this->fin = fin;
  this->fout = fout;
  this->ispadding = ispadding;
  this->buflst = new iobuffer[size];
  std::lock_guard<std::mutex> lock(mtx);
  for (u32_t i = 0; i < size; ++i)
    state[i] = EMPTY;
  over = false;
  read_done = false;
  total_chunks = 0;
};

/*################################
  工作线程接口
################################*/


/*
wait_loaded:等待缓冲区被装载
id:工作线程标号
*/

void buffergroup::wait_loaded(const u8_t id)
{
  std::unique_lock<std::mutex> locker(mtx);
  cv_loaded.wait(locker, [&] { return state[id] == LOADED || read_done; });
  locker.unlock();
}


/*
stop_worker:判断工作线程是否应退出
id:工作线程标号
return:true表示读线程已结束且本缓冲无新数据
*/
bool buffergroup::stop_worker(const u8_t id)
{
  std::lock_guard<std::mutex> locker(mtx);
  return read_done && state[id] != LOADED;
}
/*
get_entry:获取缓冲区下一个表项
id:工作线程标号
return:表项地址,若缓冲区已经读取完毕返回NULL
*/
u8_t *buffergroup::get_entry(const u8_t id)
{
  return buflst[id].get_entry();
}
/*
finish_chunk:标记本块已处理完毕
id:工作线程标号
return:true表示读线程已结束,本块为最后一块,工作线程应退出
*/
bool buffergroup::finish_chunk(const u8_t id)
{
  std::lock_guard<std::mutex> locker(mtx);
  state[id] = PROCESSED;
  cv_processed.notify_all();
  return read_done;
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
      cv_loaded.notify_all();
      if (over)
        break;
    }
  }
}

/*################################
  写线程
################################*/
/*
run_write:写线程,按chunk序号顺序导出
printload:过程打印函数
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
    {
      std::unique_lock<std::mutex> locker(mtx);
      cv_processed.wait(locker, [&] {
        return state[id] == PROCESSED || (read_done && next == total_chunks);
      });
      if (read_done && next == total_chunks)
        break;
    }
    PROF_LOG("WRITE_BEGIN", next);
    u32_t n = buflst[id].export_buffer(fout, ispadding);
    PROF_LOG("WRITE_END", next);
    if (hash_feed)
      hash_feed(buflst[id].get_data(), n);
    printload("Chunk " + std::to_string(next), n);
    {
      std::lock_guard<std::mutex> locker(mtx);
      state[id] = EMPTY;
      ++next;
      cv_empty.notify_all();
    }
  }
}
