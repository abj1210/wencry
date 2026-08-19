# 缓冲池与多线程调度同步逻辑说明

本文档描述重构后的多线程加解密流水线：调度层 `multicry_master` 与缓冲池层 `buffergroup` 的协作过程与同步逻辑。
- 编排层 `kernel/cry.cpp`：`runcrypt` 通过 `prepare_cryption_master` 统一装配流水线，`execute_*` 只保留「准备 → 装配 → 运行 → 回收」主线。
- 调度层 `kernel/multi_pipeline/multicry.h/.cpp`：`multicry_master` 持有输入/输出文件与三类回调，负责线程的创建与汇合。
- 缓冲池层 `kernel/multi_pipeline/buffergroup/multi_buffergroup.h/.cpp`（iobuffer 拆分为 `iobuffer.cpp`）：维护空闲池/工作池与全局序号，提供加锁的状态机原语。

## 1. 设计目标

- 缓冲从「一次性固定分配」改为「运行时按需动态分配」。
- `buffergroup` 维护两个缓冲池：**空闲池** `idle_pool` 与**工作池** `work_pool`。
- 两个池均设容量上限；为每个空闲 buffer 记录进入空闲池的时间戳以支持超时释放。
- 删除每个 buffer 的 `threadid`/`seq` 标志，改用统一全局序号 `seq` 保证有序。

## 2. 数据流

```
          ┌─────────────── 空闲池  idle_pool ───────────────┐
          │ (可复用的空 buffer, 容量上限 IDLE_POOL_MAX)      │
          └──────────────┬────────────────────▲────────────┘
                 读线程取(空则 new)          写线程回收(满/超时则释放)
                         │                    │
                         ▼                    │
              ┌───────────────────────────────┴────────────┐
              │              工作池 work_pool               │
              │  (在途 buffer, 键 = 全局序号 seq,           │
              │   容量上限 WORK_POOL_MAX, 满则读线程阻塞)    │
              └──────┬──────────────┬───────────────┬──────┘
                     │HASH按seq消费  │工作线程按      │写线程按seq写出
                     │(喂HMAC)      │seq%N领取AES    │并回收/释放
```

- 读线程从空闲池请求 buffer（空闲池空则动态 `new` 一个），装满后以全局序号 `seq` 加入工作池。
- HASH 线程按 `seq` 递增消费密文喂入 HMAC。
- 工作线程按 `seq % total_threads` 路由，领取本线程名下最小 `seq` 的就绪块做 AES。
- 写线程按 `seq` 递增写出，并将处理完毕的 buffer 从工作池移出、归还空闲池。

## 3. 各模式状态机

| 模式 | 流转 |
| --- | --- |
| 加密 | `EMPTY → LOADED → CLAIMED → PROCESSED → HASHED → EMPTY` |
| 解密 | `EMPTY → LOADED → HASHED → CLAIMED → PROCESSED → EMPTY` |
| 验证 | `EMPTY → LOADED → EMPTY`（HASH 读完即回收，不 AES 不写） |

状态 `state` 随 `iobuffer` 对象保存（不再用并行数组）。

## 4. 同步原语

- 单一 `std::mutex mtx` + 单一 `std::condition_variable cv`。
- 所有状态/池变更均持锁执行，并在末尾 `cv.notify_all()` 唤醒全部等待线程；各等待线程用谓词自旋，天然处理虚假唤醒。
- `fread`（`load_buffer`）与 `fwrite`（`export_buffer`）在锁外执行，避免长 I/O 持锁。

### 4.1 读线程 `run_read`

- 等待谓词：`work_pool.size() < WORK_POOL_MAX`（工作池未满）。
- 从空闲池取 buffer（空则 `new iobuffer`），锁外 `load_buffer` 装满。
- 加锁：分配 `seq = next++`，置 `LOADED`，`work_pool[seq] = buf`，`notify_all`。
- 读到 `FINAL`/`NODATA`：置 `total_chunks`、`read_done = true`，`notify_all`，退出。
  `NODATA`（空内容）时该空 buffer 直接 `delete`。

### 4.2 HASH 线程 `run_hash`

- 目标状态 `target`：加密 `PROCESSED`，解密/验证 `LOADED`。
- 等待谓词：`chunk_ready_locked(next, target) || (read_done && next == total_chunks)`。
- 锁外 `hash_feed(buf->get_data(), buf->data_len())` 喂入 HMAC。
- 加锁：加密/解密置 `HASHED`；验证从工作池 `erase(next)` 后 `recycle_locked` 回收。
  `++next`，`notify_all`。
- 退出时（`read_done && next == total_chunks`）`sweep_idle_locked()` 兜底清空空闲池
  （验证模式无写线程，由 HASH 线程承担清理）。

### 4.3 工作线程 `wait_loaded` / `finish_chunk`

- 就绪状态 `ready`：加密 `LOADED`，解密 `HASHED`。
- `wait_loaded(id)` 等待谓词：
  `has_claimable_locked(id, ready) || (read_done && !worker_pending_locked(id))`。
  - `has_claimable_locked`：工作池中存在 `seq % total_threads == id` 且状态为 `ready` 的块。
  - `worker_pending_locked`：本线程名下仍存在状态 ≠ `PROCESSED` 的块
    （解密中 `LOADED` 待 HASH 的块也计入，防止工作线程提前退出遗弃该块）。
- 领取：`claim_locked` 选中本线程名下最小 `seq` 的就绪块并置 `CLAIMED`，返回指针；
  无块返回 `NULL`（退出哨兵）。
- `finish_chunk(buffer)`：置 `PROCESSED`，`notify_all`。

### 4.4 写线程 `run_write`

- 就绪状态 `ready`：加密 `HASHED`，解密 `PROCESSED`。
- 等待谓词：`chunk_ready_locked(next, ready) || (read_done && next == total_chunks)`。
- 锁外 `export_buffer` 写出，`printload` 打印进度。
- 加锁：`work_pool.erase(next)`，`recycle_locked(buf)`，`++next`，`notify_all`。
- 退出时 `sweep_idle_locked()` 兜底清空空闲池。

## 5. 回收与清理 `recycle_locked` / `sweep_idle_locked`

`recycle_locked(buf)`（要求持有 `mtx`）分两阶段：

- **读取已完成（`read_done == true`）**：读线程不会再从空闲池取 buffer，
  故 `delete buf` 并 `sweep_idle_locked()` 一次性清空空闲池，内存随流水线结束收敛到 0。
- **读取进行中**：
  1. 淘汰空闲池前端 `idle_ts` 超过 `IDLE_TIMEOUT_MS` 的空闲 buffer；
  2. 若 `idle_pool.size() >= IDLE_POOL_MAX`，`delete buf`（不归还）；
  3. 否则置 `EMPTY`、记录 `idle_ts = steady_us()`、`push_back` 归还空闲池。

时间戳使用 `std::chrono::steady_clock`（微秒），单调不受系统时钟回拨影响。

## 6. 有序性与死锁安全

- **有序**：读线程分配的 `seq` 单调递增；HASH/写线程严格按 `seq` 递增消费，
  保证 HMAC 顺序与文件写出顺序正确；工作线程只需保证本线程名下按最小 `seq` 处理，
  维持链式模式（CBC/CTR/CFB/OFB）的 IV 链连续。
- **有界背压**：读线程在工作池满时阻塞，内存上界 = `(WORK_POOL_MAX + IDLE_POOL_MAX) × 16MB`。
- **无死锁**：流水线为 `读 → HASH → AES → 写` 单向 DAG；写线程回收时「空闲池满即释放、永不阻塞」，
  保证工作池始终能排空；读线程仅等下游（写/HASH）腾出工作池空间，无环。

## 7. 调度编排 (multicry_master 与 runcrypt::prepare_cryption_master)

流水线分三层协作：编排层 `runcrypt`、调度层 `multicry_master`、缓冲池层 `buffergroup`。

- `runcrypt`（编排层）在 `execute_encrypt/decrypt/verify` 中依次调用 `prepare_cryption_master` → `run_multicry` → `release`，负责装配与回收流水线。
- `multicry_master`（调度层）持有输入/输出文件 `fin/fout` 与三类回调，负责线程的创建与汇合。
- `buffergroup`（缓冲池层）提供加锁的状态机原语（见第 4、5 节），不感知文件与回调。

### 7.1 三类回调

`multicry_master` 内部持有三类回调，由编排层通过 setter 注入，实现「调度」与「业务」解耦：

| 回调 | setter | 消费线程 | 作用 |
| --- | --- | --- | --- |
| `hash_feed` | `set_hash_feed(fn)` | HASH 线程 | 将密文块喂入 HMAC（`hmachandle.feed_hash`） |
| `printload` | `set_print_load(fn)` | 写线程 | 打印进度（`resultprint->printpercentage`） |
| `aes_func[i]` | `set_aes_mode(fn, id)` | 工作线程 i | 对16字节块执行 AES（`aesmode[i]->runcry`） |

验证模式 `aes_func[i]` 注入 `nullptr`（无 AES、无写线程）。

### 7.2 prepare_cryption_master：统一装配

`runcrypt::prepare_cryption_master(aesmode, file_size, pipemode)` 集中完成流水线装配：

1. `buffergroup::get_instance()->set_buffergroup(threads_num, pipemode)` 配置缓冲池与流水线模式（不再传入 fin/fout，文件归 `multicry_master` 持有）。
2. `crym.set_hash_feed(...)` 绑定 HMAC 喂入回调。
3. `crym.set_print_load(...)` 绑定进度打印回调（把 `file_size` 捕获进闭包）。
4. 对每个工作线程 `crym.set_aes_mode(...)` 绑定 AES 回调（验证模式传 `nullptr`）。

相较旧版（在 `execute_*` 内用 `std::bind` 内联装配、`set_hash_feed` 直接挂在 `buffergroup` 上、`fin/fout` 经 `set_buffergroup` 传入），装配逻辑收敛到单一函数，调度器职责更清晰。

### 7.3 run_multicry：线程创建与汇合

`run_multicry(threads_num, mode)` 的线程编排：

```cpp
//启动:
  hash_thread = spawn run_hash                  // 恒启动(三模式共用)
  if (!verify) {                                // 加密/解密:
    threads[i]  = spawn multiruncrypt_file(i)   //   N 个工作线程
    write_thread = spawn run_write              //   1 个写线程
  }
  run_read(mode)                                // 读线程 = 当前调用线程(不额外 spawn)

//汇合(join):
  hash_thread.join()    // HASH 先汇合(按 seq 消费到 read_done && next == total_chunks 退出并兜底清理空闲池)
  write_thread.join()   // 写线程次之(写完 total_chunks 后退出)
  threads[i].join()     // 工作线程最后(wait_loaded 返回 NULL 哨兵退出)
```

关键点：

- **读线程复用调用线程**：`run_read` 直接在当前线程执行（阻塞读到 EOF），不额外 spawn，少一次线程上下文切换。
- **汇合顺序 = `读 → HASH → 写 → 工作`**：调用线程读完后先等 HASH，再等写线程，最后等各工作线程，保证所有 buffer 依序消费完毕。
- 验证模式不 spawn 工作线程与写线程，`write_thread` 为空（`joinable()` 判断跳过）。

### 7.4 回调生命周期

- **装配期**：`prepare_cryption_master` 注入三类回调。
- **运行期**：各线程按角色消费对应回调。
- **回收期**：`release()` 先 `set_hash_feed(nullptr)/set_print_load(nullptr)/set_aes_mode(nullptr, i)` 清空全部回调，再 `resetPercentage()` 复位进度、`del_instance()` 释放缓冲池单例，避免回调悬挂/复用。

## 8. 本次改进点（相对旧版）

1. **职责分层**：调度（线程/回调/文件）收敛到 `multicry_master`，缓冲池 `buffergroup` 只管状态机与内存，`runcrypt` 只管编排。`fin/fout` 从 `buffergroup::set_buffergroup` 移到 `multicry_master` 构造持有。
2. **回调显式化**：`set_hash_feed`/`set_print_load`/`set_aes_mode` 三个 setter 取代旧版内联 `std::bind` 与作为 `run_multicry` 参数的进度回调。
3. **装配收敛**：新增 `prepare_cryption_master` 统一完成 `set_buffergroup` 与三类回调注入，`execute_*` 只保留「准备 → 装配 → 运行 → 回收」四步主线。
4. **回收对称**：`release()` 对称地清空三类回调并释放缓冲池单例。
5. **接口简化**：`run_multicry(threads_num, mode)` 去掉进度回调参数；`set_buffergroup(threads_num, mode)` 去掉 fin/fout 参数。
