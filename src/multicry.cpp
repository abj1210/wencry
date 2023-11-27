#include "multicry.h"
#include "aes.h"
#include "util.h"

#include <pthread.h>
#include <stdio.h>

#ifdef MULTI_ENABLE

//缓冲区序列
struct iobuffer bufs[THREADS_NUM];
//线程序列
pthread_t threads[THREADS_NUM];
//输入输出文件
FILE *fin, *fout;
//保证同步的条件变量和互斥锁
pthread_cond_t cond;
pthread_mutex_t mutex;
//保证同步的输入输出序号
unsigned int inputidx = 0, outputidx = 0;

int tail = 0;
/*
multiencrypt_file:进行加密的线程函数
idp:线程id的地址
*/
void *multiencrypt_file(void *idp) {
  int id = *(int *)idp;
  unsigned int idxnow = 0;
  bool flag = true;
  pthread_mutex_lock(&mutex);
  if (load_files(&bufs[id], fin, fout))
    idxnow = inputidx++;
  else
    flag = false;
  pthread_mutex_unlock(&mutex);
  if (flag) {
    printf("Buffer of thread id %d loaded %dMB data.\n", id, BUF_SZ >> 16);
    fflush(stdout);
  }
  while (flag) {
    struct state *block = (struct state *)get_entry(&bufs[id]);
    if (block == NULL) {
      pthread_mutex_lock(&mutex);
      while (outputidx != idxnow && inputidx != -1)
        pthread_cond_wait(&cond, &mutex);

      if (buffer_over(&bufs[id])) {
        char sum = final_write(&bufs[id], 16);
        fseek(fout, 40, SEEK_SET);
        fwrite(&sum, 1, 1, fout);
        inputidx = -1;
      } else {
        printf("Buffer of thread id %d loaded %dMB data.\n", id, BUF_SZ >> 16);
        update_buffer(&bufs[id]);
      }

      outputidx++;
      if (inputidx == -1)
        flag = false;
      else
        idxnow = inputidx++;

      pthread_cond_broadcast(&cond);
      pthread_mutex_unlock(&mutex);
      fflush(stdout);
    } else
      runaes_128bit(*block);
  }
  pthread_exit(NULL);
}
/*
multidecrypt_file:负责解密的线程函数
idp:线程id的地址
*/
void *multidecrypt_file(void *idp) {
  int id = *(int *)idp;
  unsigned int idxnow = 0;
  bool flag = true;
  pthread_mutex_lock(&mutex);
  if (load_files(&bufs[id], fin, fout))
    idxnow = inputidx++;
  else
    flag = false;
  pthread_mutex_unlock(&mutex);
  if (flag) {
    printf("Buffer of thread id %d loaded %dMB data.\n", id, BUF_SZ >> 16);
    fflush(stdout);
  }

  while (flag) {
    struct state *block = (struct state *)get_entry(&bufs[id]);
    if (block == NULL) {
      pthread_mutex_lock(&mutex);
      while (outputidx != idxnow && inputidx != -1)
        pthread_cond_wait(&cond, &mutex);

      if (buffer_over(&bufs[id])) {
        final_write(&bufs[id], tail);
        inputidx = -1;
      } else {
        printf("Buffer of thread id %d loaded %dMB data.\n", id, BUF_SZ >> 16);
        update_buffer(&bufs[id]);
      }

      outputidx++;
      if (inputidx == -1)
        flag = false;
      else
        idxnow = inputidx++;

      pthread_cond_broadcast(&cond);
      pthread_mutex_unlock(&mutex);
      fflush(stdout);
    } else
      decaes_128bit(*block);
  }
  pthread_exit(NULL);
}
/*
接口函数
multienc_master:进行并发加密的函数
fp:输入文件地址
fout:输出文件地址
threads_num:并发线程数
*/
void multienc_master(FILE *fp, FILE *out, int threads_num) {
  fin = fp;
  fout = out;
  pthread_mutex_init(&mutex, NULL);
  pthread_cond_init(&cond, NULL);
  int tids[THREADS_NUM];
  for (int i = 0; i < threads_num; i++) {
    tids[i] = i;
    pthread_create(&threads[i], NULL, multiencrypt_file, &tids[i]);
  }
  for (int i = 0; i < threads_num; i++) {
    pthread_join(threads[i], NULL);
  }
  pthread_mutex_destroy(&mutex);
  pthread_cond_destroy(&cond);
}
/*
接口函数
multidec_master:进行并发解密的函数
fp:输入文件地址
fout:输出文件地址
tailin:最后一单元项写入的字节数
threads_num:并发线程数
*/
void multidec_master(FILE *fp, FILE *out, int tailin, int threads_num) {
  fin = fp;
  fout = out;
  tail = tailin;
  fseek(fp, 41, SEEK_SET);
  pthread_mutex_init(&mutex, NULL);
  pthread_cond_init(&cond, NULL);
  int tids[THREADS_NUM];
  for (int i = 0; i < threads_num; i++) {
    tids[i] = i;
    pthread_create(&threads[i], NULL, multidecrypt_file, &tids[i]);
  }
  for (int i = 0; i < threads_num; i++) {
    pthread_join(threads[i], NULL);
  }
  pthread_mutex_destroy(&mutex);
  pthread_cond_destroy(&cond);
}

#endif
