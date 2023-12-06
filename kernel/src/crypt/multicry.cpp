#include "multicry.h"
#include "aes.h"
#include "key.h"
#include <thread>
buffergroup *bg;
keyhandle *keyh;
const u8_t *aes_r_hash;
/*
multiencrypt_file:进行加密的线程函数
id:线程id
tailin:最后一单元项写入的字节数的地址
*/
void multiencrypt_file(u8_t id, u8_t *tailin) {
  encryaes aes(keyh, aes_r_hash);
  while (true) {
    state_t *block = (state_t *)bg->require_buffer_entry(id);
    if (block == NULL) {
      if (bg->judge_over(id, *tailin) || (!bg->update_lst(id)))
        break;
    } else
      aes.encryaes_128bit(block);
  }
  return;
}
/*
multidecrypt_file:负责解密的线程函数
id:线程id
tailin:最后一单元项写入的字节数的地址
*/
void multidecrypt_file(u8_t id, u8_t *tailin) {
  decryaes aes(keyh, aes_r_hash);
  while (true) {
    state_t *block = (state_t *)bg->require_buffer_entry(id);
    if (block == NULL) {
      if (bg->judge_over(id, *tailin) || (!bg->update_lst(id)))
        break;
    } else
      aes.decryaes_128bit(block);
  }
  return;
}
/*
multi_master_init:多线程初始化
key:密钥
buf:缓冲区组
r_hash:随机缓冲哈希
*/
static void multi_master_init(u8_t *key, buffergroup *buf,
                              const u8_t *r_hash) {
  keyh = new keyhandle(key);
  bg = buf;
  aes_r_hash = r_hash;
}
/*
multi_master_run:多线程运行
multifunc:并发执行的函数指针
threads_num:并发线程数
tail:最后一单元项写入的字节数
return:最后一单元实际装载的字节数
*/
static u8_t multi_master_run(void (*multifunc)(u8_t, u8_t *), const u8_t threads_num, u8_t tail) {
  std::thread threads[threads_num];
  for (u8_t i = 0; i < threads_num; ++i)
    threads[i] = std::thread(multifunc, i, &tail);
  for (u8_t i = 0; i < threads_num; ++i)
    threads[i].join();
  delete keyh;
  return tail;
}
/*
接口函数
multienc_master:进行并发加密的函数
key:密钥
buf:缓冲区组
r_hash:随机缓冲哈希
threads_num:并发线程数
tail:最后一单元项写入的字节数
*/
void multienc_master(u8_t *key, buffergroup *buf, const u8_t *r_hash, const u8_t threads_num,
                     u8_t &tail) {
  multi_master_init(key, buf, r_hash);
  tail = multi_master_run(multiencrypt_file, threads_num, tail);
}
/*
接口函数
multidec_master:进行并发解密的函数
key:密钥
buf:缓冲区组
r_hash:随机缓冲哈希
threads_num:并发线程数
tail:最后一单元项写入的字节数
*/
void multidec_master(u8_t *key, buffergroup *buf, const u8_t *r_hash, const u8_t threads_num,
                     const u8_t tail) {
  multi_master_init(key, buf, r_hash);
  multi_master_run(multidecrypt_file, threads_num, tail);
}