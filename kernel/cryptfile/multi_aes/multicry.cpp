#include "multicry.h"
/*
构造函数:配置缓冲区和加密模式
*/
multicry_master::multicry_master(FILE *fp, FILE *out, u8_t *key, const u8_t *iv, u8_t ctype, u8_t thread_num,
                                 bool isenc, bool no_echo) : THREADS_NUM(thread_num), bg(thread_num, no_echo),
                                                             fp(fp), out(out), isenc(isenc)
{
  for (int i = 0; i < THREADS_NUM; ++i)
    am[i] = selectCryptMode(key, iv + (20 * i), ctype);
};
/*
析构函数
*/
multicry_master::~multicry_master()
{
  for (int i = 0; i < THREADS_NUM; ++i)
    delete am[i];
}
/*
load_iv:加载新的初始向量
iv:新的初始向量
*/
void multicry_master::load_iv(u8_t *iv)
{
  for (int i = 0; i < THREADS_NUM; ++i)
    am[i]->resetIV(iv + (20 * i));
}
/*
multiruncrypt_file:进行加解密的线程函数
id:线程id
cm:多线程处理类
*/
void multiruncrypt_file(u8_t id, multicry_master *cm)
{
  while (true)
  {
    u8_t *block = cm->bg.require_buffer_entry(id);
    if (block == NULL)
    {
      if (cm->bg.judge_over(id) || (!cm->bg.update_lst(id)))
        break;
    }
    else
      cm->process(id, block);
  }
  return;
}
/*
run_multicry:进行多线程并发
*/
void multicry_master::run_multicry()
{
  bg.load_files(fp, out, isenc);
  for (u8_t i = 0; i < THREADS_NUM; ++i)
    threads[i] = std::thread(multiruncrypt_file, i, this);
  for (u8_t i = 0; i < THREADS_NUM; ++i)
    threads[i].join();
}
