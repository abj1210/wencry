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
构造函数:初始化缓冲区和加密器
*/
multicry_master::multicry_master(FILE *fp, FILE *out, u8_t *key, const u8_t *iv,
                                 u8_t ctype, bool isenc)
    : bg(THREADS_NUM, fp, out, isenc) {
  for (int i = 0; i < THREADS_NUM; ++i)
    am[i] = selectCryptMode(key, iv + (20 * i), ctype);
};
/*
析构函数
*/
multicry_master::~multicry_master() {
  for (int i = 0; i < THREADS_NUM; ++i)
    delete am[i];
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
