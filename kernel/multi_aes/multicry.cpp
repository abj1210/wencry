#include "multicry.h"
/*
multiruncrypt_file:进行加解密的线程函数
id:线程id
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
mode:生成的加密算法序列
printload:过程打印函数
*/
void multicry_master::run_multicry(Aesmode **mode, const std::function<void(std::string, double)> &printload)
{
  for (u8_t i = 0; i < THREADS_NUM; ++i)
    threads[i] = std::thread(multiruncrypt_file, i, std::ref((*mode[i])));
  buffergroup::get_instance()->run_buffer(printload);
  for (u8_t i = 0; i < THREADS_NUM; ++i)
    threads[i].join();
};