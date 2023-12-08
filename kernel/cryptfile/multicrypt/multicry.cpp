#include "multicry.h"
#include "multi_buffergroup.h"
#include "aes.h"
#include <thread>
buffergroup *bg;
u8_t *keyh;
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
multi_master_run:多线程运行
multifunc:并发执行的函数指针
tail:最后一单元项写入的字节数
return:最后一单元实际装载的字节数
*/
static u8_t multi_master_run(void (*multifunc)(u8_t, u8_t *), u8_t tail) {
  std::thread threads[THREADS_NUM];
  for (u8_t i = 0; i < THREADS_NUM; ++i)
    threads[i] = std::thread(multifunc, i, &tail);
  for (u8_t i = 0; i < THREADS_NUM; ++i)
    threads[i].join();
  return tail;
}
/*
接口函数
multienc_master:进行并发加密的函数
key:密钥
buf:缓冲区组
r_hash:随机缓冲哈希
tail:最后一单元项写入的字节数
*/
void multienc_master(FILE * fp, FILE * out, u8_t *key, const u8_t *r_hash,
                     u8_t &tail) {
  keyh = key, bg= new buffergroup(THREADS_NUM, fp, out), aes_r_hash = r_hash;
  tail = multi_master_run(multiencrypt_file, tail);
  delete bg;
}
/*
接口函数
multidec_master:进行并发解密的函数
key:密钥
buf:缓冲区组
r_hash:随机缓冲哈希
tail:最后一单元项写入的字节数
*/
void multidec_master(FILE * fp, FILE * out, u8_t *key, const u8_t *r_hash,
                     const u8_t tail) {
  keyh = key, bg=new buffergroup(THREADS_NUM, fp, out), aes_r_hash = r_hash;
  multi_master_run(multidecrypt_file, tail);
  delete bg;
}