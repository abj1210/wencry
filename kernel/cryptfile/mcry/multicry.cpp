#include "multicry.h"
/*
multiruncrypt_file:进行加解密的线程函数
id:线程id
cm:多线程处理类
*/
void multiruncrypt_file(u8_t id, multicry_master *cm) {
  while (true) {
    u8_t *block = cm->bg.require_buffer_entry(id);
    if (block == NULL) {
      if (cm->bg.judge_over(id) || (!cm->bg.update_lst(id)))
        break;
    } else
      cm->process(id, block);
  }
  return;
}
/*
run_multicry:进行多线程并发
*/
void multicry_master::run_multicry() {
  for (u8_t i = 0; i < THREADS_NUM; ++i)
    threads[i] = std::thread(multiruncrypt_file, i, this);
  for (u8_t i = 0; i < THREADS_NUM; ++i)
    threads[i].join();
}
