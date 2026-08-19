#include "multicry.h"

#ifdef _WIN32
#include <windows.h>
#endif

#ifdef PROFILE_THREADS
extern thread_local const char *g_thread_role;
#endif

/*################################
  读线程
################################*/
/*
run_read:读线程,按序装载chunk并分配全局序号
printload:过程打印函数
工作池满则阻塞(背压);空闲池空则动态 new 一个 buffer。
*/
void multicry_master::run_read(pipe_mode mode)
{
#ifdef _WIN32
  SetThreadDescription(GetCurrentThread(), L"ReadThread");
#endif
#ifdef PROFILE_THREADS
  g_thread_role = "read";
#endif
  u64_t next = 0;
  bool ispadding = (mode == PIPE_ENCRYPT);
  buffergroup * bg = buffergroup::get_instance();
  while (true)
  {
    iobuffer *buf = bg->wait_idle_buffer();
    PROF_LOG("LOAD_BEGIN", next);
    loadstate_t ls = buf->load_buffer(fin, ispadding);
    PROF_LOG("LOAD_END", next);
    if(bg->finish_reading(buf, ls, next++))
      break;
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
void multicry_master::run_write(pipe_mode mode)
{
#ifdef _WIN32
  SetThreadDescription(GetCurrentThread(), L"WriteThread");
#endif
#ifdef PROFILE_THREADS
  g_thread_role = "write";
#endif
  u64_t next = 0;
  bool ispadding = (mode == PIPE_ENCRYPT);
  buffergroup * bg = buffergroup::get_instance();
  while (true)
  {
    iobuffer *buf = bg->wait_processed_buffer(next);
    if(bg->stop_worker(buf))
      break;
    PROF_LOG("WRITE_BEGIN", next);
    u32_t n = buf->export_buffer(fout, ispadding);
    PROF_LOG("WRITE_END", next);
    printload("Chunk " + std::to_string(next), n);
    bg->finish_writing(buf);
    next++;
  }
}


/*################################
  HASH线程
################################*/
/*
run_hash:HASH线程,按全局序号顺序消费密文并喂入HMAC
加密读 AES 后的 PROCESSED 密文;解密/验证读 LOADED 密文(先于AES覆盖)。
验证模式读完即回收(回收逻辑由 recycle_locked 处理);加密/解密置 HASHED 交给下一级。
*/
void multicry_master::run_hash()
{
#ifdef _WIN32
  SetThreadDescription(GetCurrentThread(), L"HashThread");
#endif
#ifdef PROFILE_THREADS
  g_thread_role = "hash";
#endif
  u64_t next = 0;
  buffergroup *bg = buffergroup::get_instance();
  while (true)
  {
    iobuffer *buffer = bg->wait_unhashed(next);
    if (bg->stop_worker(buffer))
      break;
    if (hash_feed)
      hash_feed(buffer->get_data(), buffer->data_len());
    bg->finish_hashing(buffer);
    next++;
  }
}

/*################################
  工作线程
################################*/
/*
multiruncrypt_file:进行加解密的线程函数
id:线程id
*/
void multicry_master::multiruncrypt_file(u8_t id)
{
#ifdef _WIN32
  wchar_t name[16];
  swprintf(name, 16, L"Worker%d", (int)id);
  SetThreadDescription(GetCurrentThread(), name);
#endif
#ifdef PROFILE_THREADS
  g_thread_role = "worker";
#endif
  buffergroup *bg = buffergroup::get_instance();
  while (true)
  {
    iobuffer *buffer = bg->wait_loaded(id);
    // 哨兵(NULL)表示本线程已无任务,退出。
    if (bg->stop_worker(buffer))
      break;
    PROF_LOG("AES_BEGIN", id);
    for (u8_t *block = buffer->get_entry(); block != NULL; block = buffer->get_entry())
      aes_func[id](block);
    PROF_LOG("AES_END", id);
    // 处理完当前块后继续循环排空本线程名下剩余的就绪块,
    // 收尾统一由 wait_loaded/stop_worker 的 NULL 哨兵判定;不能因 read_done 提前退出,
    // 否则工作池中尚未处理的块会被遗弃,导致写线程死锁。
    bg->finish_chunk(buffer);
  }
};


/*################################
  线程并发
################################*/
/*
run_multicry:进行多线程并发(读线程--工作线程--写线程流水线)
threads_num:工作线程数
mode:生成的加密算法序列
printload:过程打印函数
*/
void multicry_master::run_multicry(u8_t threads_num, pipe_mode mode)
{
  bool is_verify = (mode == PIPE_VERIFY);
  // HASH线程在三种模式下都运行
  std::thread hash_thread(&multicry_master::run_hash, this);
  std::thread write_thread;
  if (!is_verify)
  {
    for (u8_t i = 0; i < threads_num; ++i)
      threads[i] = std::thread(&multicry_master::multiruncrypt_file, this, i);
    write_thread = std::thread(&multicry_master::run_write, this, mode);
  }
  run_read(mode);
  hash_thread.join();
  if (write_thread.joinable())
    write_thread.join();
  for (u8_t i = 0; i < threads_num; ++i)
    if (threads[i].joinable())
      threads[i].join();
};
