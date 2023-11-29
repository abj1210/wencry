#include "multicry.h"
#include "aes.h"
#include "Autil.h"

#ifdef MULTI_ENABLE
#include <condition_variable>
#include <mutex>
#include <stdio.h>
#include <thread>

//缓冲区序列
struct iobuffer bufs[THREADS_NUM];
//输入输出文件
FILE *fin, *fout;
//保证同步的条件变量和互斥锁
std::condition_variable cond;
std::mutex mutexA;
//保证同步的输入输出序号
int inputidx = 0, outputidx = 0;

int tail = 0;
/*
idx_update:更新并获取序号
return:返回的序号
*/
int idx_update() {
  outputidx++;
  if (inputidx == -1)
    return -1;
  else
    return inputidx++;
}
/*
multiencrypt_file:进行加密的线程函数
id:线程id
*/
void multiencrypt_file(int id) {
  //获取初始缓冲区块
  mutexA.lock();
  int idxnow = load_files(&bufs[id], fin, fout) ? inputidx++ : -1;
  mutexA.unlock();
  if (idxnow != -1)
    printf("Buffer of thread id %d loaded %dMB data.\n", id, BUF_SZ >> 16);
  //循环处理
  while (idxnow != -1) {
    //获取待处理表项
    struct state *block = (struct state *)get_entry(&bufs[id]);
    //检查表项是否为NULL
    if (block == NULL) {
      //如果是,则表明当前缓冲区块处理完毕
      //上锁以进行线程同步
      std::unique_lock<std::mutex> locker(mutexA);
      //等待需求索引号与当前持有的索引号相同或处理已经结束
      while (outputidx != idxnow && inputidx != -1)
        cond.wait(locker);
      //等待结束,表明此时当前处理的缓冲区块可以插入输出文件中
      //判断处理是否结束
      if (buffer_over(&bufs[id])) {
        //若结束,进行最终写入并将输入序号置为-1以表示输入结束
        char sum = final_write(&bufs[id], 16);
        fseek(fout, 47, SEEK_SET);
        fwrite(&sum, 1, 1, fout);
        inputidx = -1;
      } else if (inputidx != -1)//否则进行更新,将当前缓冲区块写入输出文件并从输入文件获取新的缓冲区块
        update_buffer(&bufs[id]);
      //分配新块的索引号并将输出的需求索引号加1,通知其他线程检查条件后解锁
      idxnow = idx_update();
      cond.notify_all();
      locker.unlock();
      //打印进度
      if (idxnow != -1)
        printf("Buffer of thread id %d loaded %dMB data.\n", id, BUF_SZ >> 16);
    } else//否则处理表项
      runaes_128bit(*block);
  }
}
/*
multidecrypt_file:负责解密的线程函数
id:线程id
*/
void multidecrypt_file(int id) {
  mutexA.lock();
  int idxnow = load_files(&bufs[id], fin, fout) ? inputidx++ : -1;
  mutexA.unlock();
  if (idxnow != -1)
    printf("Buffer of thread id %d loaded %dMB data.\n", id, BUF_SZ >> 16);

  while (idxnow != -1) {
    struct state *block = (struct state *)get_entry(&bufs[id]);
    if (block == NULL) {
      std::unique_lock<std::mutex> locker(mutexA);
      while (outputidx != idxnow && inputidx != -1)
        cond.wait(locker);
      if (buffer_over(&bufs[id])) {
        final_write(&bufs[id], tail);
        inputidx = -1;
      } else if (inputidx != -1)
        update_buffer(&bufs[id]);
      idxnow = idx_update();
      cond.notify_all();
      locker.unlock();
      if (idxnow != -1)
        printf("Buffer of thread id %d loaded %dMB data.\n", id, BUF_SZ >> 16);
    } else
      decaes_128bit(*block);
  }
}
/*
multi_master_init:多线程初始化
fp:输入文件地址
fout:输出文件地址
tailin:最后一单元项写入的字节数
*/
void multi_master_init(FILE *fp, FILE *out, int tailin) {
  fin = fp;
  fout = out;
  tail = tailin;
}
/*
接口函数
multienc_master:进行并发加密的函数
fp:输入文件地址
fout:输出文件地址
threads_num:并发线程数
*/
void multienc_master(FILE *fp, FILE *out, int threads_num) {
  //初始化
  multi_master_init(fp, out, 16);
  //线程创建
  std::thread threads[THREADS_NUM];
  for (int i = 0; i < threads_num; i++)
    threads[i] = std::thread(multiencrypt_file, i);
  //等待线程执行完毕
  for (int i = 0; i < threads_num; i++)
    threads[i].join();
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
  multi_master_init(fp, out, tailin);
  std::thread threads[THREADS_NUM];
  for (int i = 0; i < threads_num; i++)
    threads[i] = std::thread(multidecrypt_file, i);
  for (int i = 0; i < threads_num; i++)
    threads[i].join();
}
#endif