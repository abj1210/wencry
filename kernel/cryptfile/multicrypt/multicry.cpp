#include "multicry.h"
#include "aes.h"
#include "multi_buffergroup.h"
#include <thread>
/*
multiruncrypt_file:进行加解密的线程函数
id:线程id
tailin:最后一单元项写入的字节数的地址
runaes:加解密处理类
bg:缓冲区组
*/
void multiruncrypt_file(u8_t id, u8_t *tailin, aeshandle *runaes,
                        buffergroup *bg) {
  while (true) {
    state_t *block = (state_t *)bg->require_buffer_entry(id);
    if (block == NULL) {
      if (bg->judge_over(id, *tailin) || (!bg->update_lst(id)))
        break;
    } else
      runaes->runaes_128bit(block);
  }
  return;
}
/*
接口函数
multienc_master:进行并发加密的函数
fp:输入文件指针
fout:输出文件指针
key:密钥
r_hash:随机缓冲哈希
tail:最后一单元项写入的字节数
*/
void multienc_master(FILE *fp, FILE *out, u8_t *key, const u8_t *r_hash,
                     u8_t &tail) {
  encryaes *aes[THREADS_NUM];
  buffergroup bg(THREADS_NUM, fp, out);
  std::thread threads[THREADS_NUM];
  for (u8_t i = 0; i < THREADS_NUM; ++i)
    CREATE_THREAD(encry)
  for (u8_t i = 0; i < THREADS_NUM; ++i)
    JOIN_THREAD
}
/*
接口函数
multidec_master:进行并发解密的函数
fp:输入文件指针
fout:输出文件指针
key:密钥
r_hash:随机缓冲哈希
tail:最后一单元项写入的字节数
*/
void multidec_master(FILE *fp, FILE *out, u8_t *key, const u8_t *r_hash,
                     u8_t tail) {
  decryaes *aes[THREADS_NUM];
  buffergroup bg(THREADS_NUM, fp, out);
  std::thread threads[THREADS_NUM];
  for (u8_t i = 0; i < THREADS_NUM; ++i)
    CREATE_THREAD(decry)
  for (u8_t i = 0; i < THREADS_NUM; ++i)
    JOIN_THREAD
}