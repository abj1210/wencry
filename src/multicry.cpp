#include "multicry.h"
#include "aes.h"
#include "multi_buffergroup.h"
#include <thread>
buffergroup *bg;
keyhandle *keyh;
/*
multiencrypt_file:进行加密的线程函数
id:线程id
tailin:最后一单元项写入的字节数的地址
*/
void multiencrypt_file(int id, u8_t *tailin) {
  encryaes aes(keyh);
  while (true) {
    state_t *block = (state_t *)bg->require_buffer_entry(id);
    if (block == NULL) {
      *tailin = bg->judge_over(id, 16);
      if ((*tailin != 0) || (!bg->update_lst(id)))
        break;
    } else
      aes.encryaes_128bit(*block);
  }
  return;
}
/*
multidecrypt_file:负责解密的线程函数
id:线程id
tailin:最后一单元项写入的字节数的地址
*/
void multidecrypt_file(int id, u8_t *tailin) {
  decryaes aes(keyh);
  while (true) {
    state_t *block = (state_t *)bg->require_buffer_entry(id);
    if (block == NULL) {
      if ((bg->judge_over(id, *tailin) != 0) || (!bg->update_lst(id)))
        break;
    } else
      aes.decryaes_128bit(*block);
  }
  return;
}
/*
multi_master_init:多线程初始化
key:密钥
buf:缓冲区组
*/
void multi_master_init(keyhandle *key, buffergroup *buf) {
  keyh = key;
  bg = buf;
}
/*
multi_master_run:多线程运行
threads_num:并发线程数
tail:最后一单元项写入的字节数
multifunc:并发执行的函数指针
*/
u8_t multi_master_run(const int threads_num, u8_t tail,
                      void (*multifunc)(int, u8_t *)) {
  std::thread *threads = new std::thread[threads_num];
  u8_t list[THREADS_NUM], res = 0;
  for (int i = 0; i < threads_num; ++i) {
    list[i] = tail;
    threads[i] = std::thread(multifunc, i, &list[i]);
  }
  for (int i = 0; i < threads_num; ++i) {
    threads[i].join();
    res = list[i] > res ? list[i] : res;
  }
  delete[] threads;
  return res;
}
/*
接口函数
multienc_master:进行并发加密的函数
key:密钥
buf:缓冲区组
threads_num:并发线程数
*/
void multienc_master(keyhandle *key, buffergroup *buf, u8_t &tail) {
  multi_master_init(key, buf);
  tail = multi_master_run(THREADS_NUM, tail, multiencrypt_file);
}
/*
接口函数
multidec_master:进行并发解密的函数
key:密钥
buf:缓冲区组
tail:最后一单元项写入的字节数
*/
void multidec_master(keyhandle *key, buffergroup *buf, u8_t &tail) {
  multi_master_init(key, buf);
  multi_master_run(THREADS_NUM, tail, multidecrypt_file);
}