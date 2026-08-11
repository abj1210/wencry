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
    iobuffer->wait_loaded(id);
    if (iobuffer->stop_worker(id))
      break;
    PROF_LOG("AES_BEGIN", id);
    for (u8_t *block = iobuffer->get_entry(id); block != NULL; block = iobuffer->get_entry(id))
      mode.runcry(block);
    PROF_LOG("AES_END", id);
    if (iobuffer->finish_chunk(id))
      break;
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
  for (u8_t i = 0; i < threads_num; ++i)
    threads[i] = std::thread(multiruncrypt_file, i, std::ref(*mode[i]));
  std::thread write_thread(&buffergroup::run_write, buffergroup::get_instance(), printload);
  buffergroup::get_instance()->run_read(printload);
  write_thread.join();
  for (u8_t i = 0; i < threads_num; ++i)
    threads[i].join();
};
