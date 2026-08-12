#include "multicry.h"

#ifdef _WIN32
#include <windows.h>
#endif

#ifdef PROFILE_THREADS
extern thread_local const char *g_thread_role;
#endif

/*
multiruncrypt_file:进行加解密的线程函数
id:线程id
mode:生成的加密算法
*/
void multiruncrypt_file(u8_t id, Aesmode &mode)
{
#ifdef _WIN32
  wchar_t name[16];
  swprintf(name, 16, L"Worker%d", (int)id);
  SetThreadDescription(GetCurrentThread(), name);
#endif
#ifdef PROFILE_THREADS
  g_thread_role = "worker";
#endif
  buffergroup *iobuffer = buffergroup::get_instance();
  while (true)
  {
    u8_t buffer_id = iobuffer->wait_loaded(id);
    // 哨兵(size 及以上的非法值)表示本线程已无任务,退出。
    if (iobuffer->stop_worker(buffer_id))
      break;
    PROF_LOG("AES_BEGIN", id);
    for (u8_t *block = iobuffer->get_entry(buffer_id); block != NULL; block = iobuffer->get_entry(buffer_id))
      mode.runcry(block);
    PROF_LOG("AES_END", id);
    // 处理完当前块后继续循环排空本线程名下剩余的 LOADED 块,
    // 收尾统一由 wait_loaded/stop_worker 的哨兵判定;不能因 read_done 提前退出,
    // 否则冗余缓冲中尚未处理的块会被遗弃,导致写线程在 judge_buffer_full 上死锁。
    iobuffer->finish_chunk(buffer_id);
  }
};
/*
run_multicry:进行多线程并发(读线程--工作线程--写线程流水线)
threads_num:工作线程数
mode:生成的加密算法序列
printload:过程打印函数
*/
void multicry_master::run_multicry(u8_t threads_num, Aesmode **mode, const std::function<void(std::string, size_t)> &printload)
{
  buffergroup *bg = buffergroup::get_instance();
  bool is_verify = (bg->get_mode() == PIPE_VERIFY);
  // HASH线程在三种模式下都运行
  std::thread hash_thread(&buffergroup::run_hash, bg, printload);
  std::thread write_thread;
  if (!is_verify)
  {
    for (u8_t i = 0; i < threads_num; ++i)
      threads[i] = std::thread(multiruncrypt_file, i, std::ref(*mode[i]));
    write_thread = std::thread(&buffergroup::run_write, bg, printload);
  }
  bg->run_read(printload);
  hash_thread.join();
  if (write_thread.joinable())
    write_thread.join();
  for (u8_t i = 0; i < threads_num; ++i)
    if (threads[i].joinable())
      threads[i].join();
};
