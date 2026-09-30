#include "multicry.h"

#ifdef _WIN32
#include <windows.h>
#endif

#ifdef LOG_SCHED
thread_local const char *g_sched_role = NULL;
#endif

/*################################
  读线程
################################*/
/*
runReader:读线程,按序装载chunk并分配全局序号
mode:流水线模式
从空闲池认领 buffer(认领时即移出空闲池),fread 装满后由 finishLoading 移入工作池;
工作池+已处理池达到 WORK_PROCESSED_MAX 时阻塞(背压)。
*/
void MulticryMaster::runReader(pipe_mode mode)
{
#ifdef _WIN32
  SetThreadDescription(GetCurrentThread(), L"ReadThread");
#endif
#ifdef LOG_SCHED
  g_sched_role = "read";
#endif
  u64_t next = 0;
  bool ispadding = (mode == PIPE_ENCRYPT);
  BufferGroup * bg = BufferGroup::getInstance();
  while (true)
  {
    IoBuffer *buf = bg->recvIdlePool(next);
    SCHED_LOG(g_sched_role, "LOAD_BEGIN", -1, (long long)next, "", -1, -1, -1);
    loadstate_t ls = buf->loadBuffer(fin, ispadding);
    SCHED_LOG(g_sched_role, "LOAD_END", -1, (long long)next, "", -1, -1, -1);
    // 登记已装载块(FINAL/NODATA 时在锁内置位 read_done,避免末块与"读取结束"出现空窗);
    // 返回 true 表示本线程已读到末尾,应退出。
    if (bg->finishLoading(buf, ls, next))
      break;
    ++next;   // 下一个块的全局序号
  }
}

/*################################
  写线程
################################*/
/*
runWriter:写线程,按全局序号顺序导出
mode:流水线模式
加密/解密均按序写入已处理池的缓冲;验证模式不写文件。
写出后回收 buffer:读取完成后直接释放,否则归还空闲池(池满同样直接释放)。
*/
void MulticryMaster::runWriter(pipe_mode mode)
{
#ifdef _WIN32
  SetThreadDescription(GetCurrentThread(), L"WriteThread");
#endif
#ifdef LOG_SCHED
  g_sched_role = "write";
#endif
  u64_t next = 0;
  bool ispadding = (mode == PIPE_ENCRYPT);
  BufferGroup * bg = BufferGroup::getInstance();
  while (true)
  {
    IoBuffer *buf = bg->recvProcessedPool(next);
    if(bg->stopWorker(buf))
      break;
    if(mode != PIPE_VERIFY){
      SCHED_LOG(g_sched_role, "WRITE_BEGIN", -1, (long long)next, "", -1, -1, -1);
      u32_t n = buf->exportBuffer(fout, bg->getFinalBlock(next), ispadding);
      SCHED_LOG(g_sched_role, "WRITE_END", -1, (long long)next, "", -1, -1, -1);
      written_bytes += n;
      printload("Chunk " + std::to_string(next), n);
    }
    bg->sendIdlePool(buf);
    next++;
  }
}

/*################################
  工作线程
################################*/
/*
runWorker:进行加解密的线程函数
mode:流水线模式
id:线程id
*/
void MulticryMaster::runWorker(pipe_mode mode, u8_t id)
{
#ifdef _WIN32
  wchar_t name[16];
  swprintf(name, 16, L"Worker%d", (int)id);
  SetThreadDescription(GetCurrentThread(), name);
#endif
#ifdef LOG_SCHED
  g_sched_role = "worker";
#endif
  BufferGroup *bg = BufferGroup::getInstance();
  u8_t *hash_buffer = (u8_t *)malloc(sizeof(u8_t)*hash_size+1);
  u64_t next = id;
  while (true)
  {
    IoBuffer *buffer = bg->recvWorkPool(next);
    // 哨兵(NULL)表示本线程已无任务,退出。
    if (bg->stopWorker(buffer))
      break;
    switch (mode)
    {
    case PIPE_ENCRYPT:
      SCHED_LOG(g_sched_role, "AES_BEGIN", (long long)id, -1, "", -1, -1, -1);
      for (u8_t *block = buffer->getEntry(); block != NULL; block = buffer->getEntry())
        aes_func[id](block);
      SCHED_LOG(g_sched_role, "AES_END", (long long)id, -1, "", -1, -1, -1);
      SCHED_LOG(g_sched_role, "HASH_BEGIN", (long long)id, (long long)buffer->get_seq(), "", -1, -1, -1);
      hmac_func[id](buffer->getData(), hash_buffer, buffer->dataLen(), buffer->get_seq());
      mt_func(hash_buffer, buffer->get_seq());
      SCHED_LOG(g_sched_role, "HASH_END", (long long)id, (long long)buffer->get_seq(), "", -1, -1, -1);
      break;
    case PIPE_DECRYPT:
      SCHED_LOG(g_sched_role, "HASH_BEGIN", (long long)id, (long long)buffer->get_seq(), "", -1, -1, -1);
      hmac_func[id](buffer->getData(), hash_buffer, buffer->dataLen(), buffer->get_seq());
      mt_func(hash_buffer, buffer->get_seq());
      SCHED_LOG(g_sched_role, "HASH_END", (long long)id, (long long)buffer->get_seq(), "", -1, -1, -1);
      SCHED_LOG(g_sched_role, "AES_BEGIN", (long long)id, -1, "", -1, -1, -1);
      for (u8_t *block = buffer->getEntry(); block != NULL; block = buffer->getEntry())
        aes_func[id](block);
      SCHED_LOG(g_sched_role, "AES_END", (long long)id, -1, "", -1, -1, -1);
      break;
    case PIPE_VERIFY:
      SCHED_LOG(g_sched_role, "HASH_BEGIN", (long long)id, (long long)buffer->get_seq(), "", -1, -1, -1);
      hmac_func[id](buffer->getData(), hash_buffer, buffer->dataLen(), buffer->get_seq());
      mt_func(hash_buffer, buffer->get_seq());
      SCHED_LOG(g_sched_role, "HASH_END", (long long)id, (long long)buffer->get_seq(), "", -1, -1, -1);
      break;
    default:
      break;
    }
    // 处理完当前块后继续循环排空本线程名下剩余的就绪块,
    // 收尾统一由 recvWorkPool/stopWorker 的 NULL 哨兵判定;不能因 read_done 提前退出,
    // 否则工作池中尚未处理的块会被遗弃,导致写线程死锁。
    next = bg->sendProcessedPool(buffer);
    
  }
  free(hash_buffer);
};


/*################################
  线程并发
################################*/
/*
runMulticry:进行多线程并发(读线程--工作线程--写线程流水线)
threads_num:工作线程数
mode:生成的加密算法序列
printload:过程打印函数
*/
void MulticryMaster::runMulticry(u8_t threads_num, pipe_mode mode)
{
  std::thread write_thread= std::thread(&MulticryMaster::runWriter, this, mode);
  for (u8_t i = 0; i < threads_num; ++i)
    threads[i] = std::thread(&MulticryMaster::runWorker, this, mode, i);
  runReader(mode);
  if (write_thread.joinable())
    write_thread.join();
  for (u8_t i = 0; i < threads_num; ++i)
    if (threads[i].joinable())
      threads[i].join();
};
