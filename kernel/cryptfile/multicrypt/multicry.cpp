#include "multicry.h"
/*
multiruncrypt_file:进行加解密的线程函数
id:线程id
cm:多线程处理类
*/
void multiruncrypt_file(u8_t id, multicry_master *cm) {
  while (true) {
    state_t *block = (state_t *)cm->bg.require_buffer_entry(id);
    if (block == NULL) {
      if (cm->bg.judge_over(id, cm->tail) || (!cm->bg.update_lst(id)))
        break;
    } else
      cm->aes[id]->runaes_128bit(block);
  }
  return;
}
/*
析构函数
*/
multicry_master::~multicry_master() {
  for (int i = 0; i < THREADS_NUM; ++i)
    delete aes[i];
}
/*
run_multicry:进行多线程并发
return:tail新值
*/
u8_t multicry_master::run_multicry() {
  for (u8_t i = 0; i < THREADS_NUM; ++i)
    threads[i] = std::thread(multiruncrypt_file, i, this);
  for (u8_t i = 0; i < THREADS_NUM; ++i)
    threads[i].join();
  return tail;
}
multienc_master::multienc_master(FILE *fp, FILE *out, u8_t *key,
                                 const u8_t *r_hash, const u8_t tail)
    : multicry_master(fp, out, tail) {
  for (int i = 0; i < THREADS_NUM; ++i)
    aes[i] = new encryaes(key, r_hash);
}
multidec_master::multidec_master(FILE *fp, FILE *out, u8_t *key,
                                 const u8_t *r_hash, const u8_t tail)
    : multicry_master(fp, out, tail) {
  for (int i = 0; i < THREADS_NUM; ++i)
    aes[i] = new decryaes(key, r_hash);
}
