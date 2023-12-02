#include "aes.h"
#include "multi_buffergroup.h"
#include "multicry.h"

#ifdef MULTI_ENABLE
#include <thread>
int tail = 0;
FILE *fout;
buffergroup *bg;
keyhandle *keyh;
/*
multiencrypt_file:进行加密的线程函数
id:线程id
*/
void multiencrypt_file(int id) {
  encryaes aes(keyh);
  while (true) {
    state_t *block = (state_t *)bg->require_buffer_entry(id);
    if (block == NULL) {
      char sum = bg->judge_over(id, 16);
      if (sum != 0) {
        fseek(fout, 47, SEEK_SET);
        fwrite(&sum, 1, 1, fout);
        break;
      } else if (!bg->update_lst(id))
        break;
    } else
      aes.encryaes_128bit(*block);
  }
}
/*
multidecrypt_file:负责解密的线程函数
id:线程id
*/
void multidecrypt_file(int id) {
  decryaes aes(keyh);
  while (true) {
    state_t *block = (state_t *)bg->require_buffer_entry(id);
    if (block == NULL) {
      if ((bg->judge_over(id, tail) != 0) || (!bg->update_lst(id)))
        break;
    } else
      aes.decryaes_128bit(*block);
  }
}
/*
multi_master_init:多线程初始化
fp:输入文件地址
fout:输出文件地址
key:密钥
tailin:最后一单元项写入的字节数
threads_num:并发线程数
*/
void multi_master_init(FILE *fp, FILE *out, keyhandle *key, int tailin,
                      const int threads_num) {
  fout = out;
  tail = tailin;
  keyh = key;
  bg = new buffergroup(threads_num, fp, out);
}
/*
multi_master_run:多线程运行
threads_num:并发线程数
multifunc:并发执行的函数指针
*/
void multi_master_run(const int threads_num, void (*multifunc)(int)) {
  std::thread *threads = new std::thread[threads_num];
  for (int i = 0; i < threads_num; ++i)
    threads[i] = std::thread(multifunc, i);
  for (int i = 0; i < threads_num; ++i)
    threads[i].join();
  delete[] threads;
  delete bg;
}
/*
接口函数
multienc_master:进行并发加密的函数
fp:输入文件地址
fout:输出文件地址
key:密钥
threads_num:并发线程数
*/
void multienc_master(FILE *fp, FILE *out, keyhandle *key,
                     const int threads_num) {
  multi_master_init(fp, out, key, 16, threads_num);
  multi_master_run(threads_num, multiencrypt_file);
}
/*
接口函数
multidec_master:进行并发解密的函数
fp:输入文件地址
fout:输出文件地址
key:密钥
tailin:最后一单元项写入的字节数
threads_num:并发线程数
*/
void multidec_master(FILE *fp, FILE *out, keyhandle *key, int tailin,
                     const int threads_num) {
  multi_master_init(fp, out, key, tailin, threads_num);
  multi_master_run(threads_num, multidecrypt_file);
}
#endif