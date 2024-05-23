#include "multicry.h"
/*
构造函数:配置缓冲区和加密模式
*/
multicry_master::multicry_master(FILE *fp, FILE *out, u8_t *key, u8_t ctype, u8_t thread_num, u8_t *iv,
                                bool no_echo) : THREADS_NUM(thread_num), fp(fp), out(out), isenc(isenc){};
/*
multiruncrypt_file:进行加解密的线程函数
id:线程id
cm:多线程处理类
*/
void multiruncrypt_file(u8_t id, buffergroup &iobuffer, Aesmode &mode)
{
  while (true)
  {
    u8_t *block = iobuffer.require_buffer_entry(id);
    if (block == NULL)
    {
      if (iobuffer.judge_over(id) || (!iobuffer.update_lst(id)))
        break;
    }
    else
      mode.runcry(block);
  }
  return;
}
/*
run_multicry:进行多线程并发
*/
void multicry_master::run_multicry(buffergroup &iobuffer, Aesmode **mode)
{
  for (u8_t i = 0; i < THREADS_NUM; ++i){
    threads[i] = std::thread(multiruncrypt_file, i, std::ref(iobuffer), std::ref((*mode[i])));
  }
  for (u8_t i = 0; i < THREADS_NUM; ++i){
    threads[i].join();
  }
}
/*
get_multicry_master:生成相应的加/解密器
mode:模式
return:返回的加/解密器指针
*/
multicry_master *GetCryMaster::get_multicry_master(u8_t * iv, char mode)
{

  return new multicry_master(fp, out, key, ctype, thread_num, iv, no_echo);
}