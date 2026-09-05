#ifndef SCHED_LOG_H
#define SCHED_LOG_H

/*
统一调度日志(LOG_SCHED 开关,默认关闭)
同时记录线程时间线事件与缓冲区生命周期,输出到 sched_log.csv:
  线程事件:LOAD_BEGIN/LOAD_END(读,seq=块号)、AES_BEGIN/AES_END(工作线程,id=线程号)、WRITE_BEGIN/WRITE_END(写,seq=块号)
  缓冲事件:BUF_NEW/BUF_DELETE(生成/销毁)、POP_IDLE(读线程取用空闲)、LOADED(入工作池)、
           POP_WORK(工作线程从工作池领取)、PROCESSED(入已处理池)、POP_PROCESSED(写线程取用)、EMPTY(归还空闲池);
          上述池迁移事件均有 _PRE 前置记录(迁移前后各记录一次);BUF_NEW_PRE/BUF_DELETE_AFTER 记录申请/释放前后。
列:us,role,event,id,seq,state,work,idle,processed,live
  us        : 相对进程启动的微秒时间戳
  role      : 记录该事件的线程角色(read/write/worker/?)
  event     : 事件名(RUN_START/RUN_END/BUF_NEW/BUF_NEW_PRE/BUF_DELETE/BUF_DELETE_AFTER/POP_IDLE/POP_IDLE_PRE/
              LOADED/LOADED_PRE/POP_WORK/POP_WORK_PRE/PROCESSED/PROCESSED_PRE/POP_PROCESSED/POP_PROCESSED_PRE/
              EMPTY/EMPTY_PRE/SWEEP/SWEEP_PRE/READ_DONE/LOAD_BEGIN/LOAD_END/AES_BEGIN/AES_END/HASH_BEGIN/HASH_END/
              WRITE_BEGIN/WRITE_END)
  id        : 缓冲区唯一编号(AES_* / HASH_* 事件中为工作线程号,非缓冲区事件为 -1)
  seq       : 缓冲区全局块序号(LOAD/WRITE 事件中为块号,未分配时为 -1)
  state     : 缓冲区所处阶段名(如 LOADED/CLAIMED/PROCESSED/EMPTY;非缓冲区事件携带辅助信息)
  work      : 工作池(已装载未领取)当前大小(未知为 -1)
  idle      : 空闲池当前大小(未知为 -1)
  processed : 已处理待写池当前大小(未知为 -1)
  live      : 当前存活的 buffer 数(由 SchedLog 内部计数,BUF_NEW +1、BUF_DELETE -1)
*/

#ifdef LOG_SCHED

#include <cstdio>
#include <cstring>
#include <mutex>
#include <chrono>

/* 各流水线线程设置的线程角色(见 multicry.cpp) */
extern thread_local const char *g_sched_role;

/*
SchedLog:调度日志记录器(单例)
out:CSV 文件句柄;mtx:串行化写;t0:相对时间基准(微秒)。
*/
class SchedLog
{
  FILE *out;
  std::mutex mtx;
  unsigned long long t0;
  long long live_buffers; // 内部维护的存活 buffer 数,由 BUF_NEW/BUF_DELETE 触发增减

  /* nowUs:返回当前时刻相对 epoch 的微秒数 */
  static unsigned long long nowUs()
  {
    return (unsigned long long)std::chrono::duration_cast<std::chrono::microseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
  }

public:
  /* inst:获取全局单例 */
  static SchedLog &inst()
  {
    static SchedLog s;
    return s;
  }
  /* SchedLog:构造,打开 sched_log.csv 并写表头 */
  SchedLog() : out(fopen("sched_log.csv", "w")), t0(nowUs()), live_buffers(0)
  {
    if (out)
      fprintf(out, "us,role,event,id,seq,state,work,idle,processed,live\n");
  }
  /* ~SchedLog:析构,关闭 CSV 文件 */
  ~SchedLog()
  {
    if (out)
      fclose(out);
  }
  /* log:记录一条事件(加锁串行化写) */
  void log(const char *role, const char *ev, long long id, long long seq,
           const char *state, int work, int idle, int processed)
  {
    std::lock_guard<std::mutex> lk(mtx);
    if (std::strcmp(ev, "BUF_NEW") == 0)
      ++live_buffers;
    else if (std::strcmp(ev, "BUF_DELETE") == 0)
      --live_buffers;
    if (out)
      fprintf(out, "%llu,%s,%s,%lld,%lld,%s,%d,%d,%d,%lld\n",
              (unsigned long long)(nowUs() - t0),
              role ? role : "?", ev, id, seq, state ? state : "", work, idle, processed,
              live_buffers);
  }
};

#define SCHED_LOG(role, ev, id, seq, state, work, idle, processed) \
  SchedLog::inst().log(role, ev, (long long)(id), (long long)(seq), (state), (int)(work), (int)(idle), (int)(processed))

#else

#define SCHED_LOG(role, ev, id, seq, state, work, idle, processed) ((void)0)

#endif

#endif
