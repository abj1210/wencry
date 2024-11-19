#include "multicry.h"
/*
multiruncrypt_file:进行加解密的线程函数
id:线程id
iobuffer:文件缓冲区
mode:生成的加密算法
*/
void multiruncrypt_file(u8_t id, Aesmode &mode)
{
  buffergroup *iobuffer = buffergroup::get_instance();
  for (u8_t *block = iobuffer->require_buffer_entry(id); block != NULL; block = iobuffer->require_buffer_entry(id))
    mode.runcry(block);
};
/*
run_multicry:进行多线程并发
iobuffer:文件缓冲区
mode:生成的加密算法序列
*/
void multicry_master::run_multicry(Aesmode **mode)
{
  for (u8_t i = 0; i < THREADS_NUM; ++i)
    threads[i] = std::thread(multiruncrypt_file, i, std::ref((*mode[i])));
  buffergroup::get_instance()->run_buffer();
  if (!no_echo)
    std::cout << "\r\n";
  for (u8_t i = 0; i < THREADS_NUM; ++i)
    threads[i].join();
};