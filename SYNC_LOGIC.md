# 缓冲池与多线程调度同步逻辑说明

本文档描述重构后的多线程加解密流水线：调度层 `multicry_master` 与缓冲池层 `buffergroup` 的协作过程与同步逻辑。

- 编排层 `kernel/cry.cpp`：`runcrypt` 通过 `prepare_cryption_master` 统一装配流水线。
- 调度层 `kernel/multi_pipeline/multicry.h/.cpp`：`multicry_master` 持有输入/输出文件与回调，负责线程创建与汇合。
- 缓冲池层 `kernel/multi_pipeline/buffergroup/multi_buffergroup.h/.cpp`：维护空闲池/工作池/已处理池与全局序号，提供加锁原语。

## 1. 设计目标

- 缓冲从「一次性固定分配」改为「运行时按需动态分配」。
- `buffergroup` 维护三个缓冲池：空闲池 `idle_pool`、工作池 `work_pool`、已处理池 `processed_pool`。
- 工作池与已处理池共用总在途上限 `WORK_PROCESSED_MAX`。
- 删除每个 buffer 的 `threadid`/`seq` 标志，改用统一全局序号 `seq` 保证有序。
- HMAC 由各工作线程就地计算（无独立 HASH 线程）。

## 2. 数据流

读线程从空闲池认领 buffer（空则 `new`，认领后仍留在空闲池中），`fread` 装满后移入工作池；工作线程按 `seq % total_threads` 领取本线程名下最小 `seq` 的块，AES/HMAC 完成后移入已处理池；写线程按 `seq` 递增从已处理池取出写出，并回收 buffer 到空闲池（空闲池满/超时则释放）。

## 3. 各模式流转

| 模式 | 流转 |
| --- | --- |
| 加密 | `EMPTY → LOADED → (工作线程 AES+HMAC) → PROCESSED → 写出 → EMPTY` |
| 解密 | `EMPTY → LOADED → (工作线程 HMAC+AES) → PROCESSED → 写出 → EMPTY` |
| 验证 | `EMPTY → LOADED → (工作线程 HMAC) → PROCESSED → 回收 → EMPTY` |

## 4. 同步原语

- 单一 `std::mutex mtx` + 单一 `std::condition_variable cv`。
- 所有状态/池变更均持锁执行，末尾 `cv.notify_all()`；等待方用谓词自旋。
- `fread` / `fwrite` 在锁外执行。

### 4.1 读线程 `run_read`

- `wait_idle_buffer()`：空闲池空则 `new iobuffer` 并放入空闲池；否则取空闲池前端；标记 `claimed=true` 后返回（buffer 仍留在空闲池中）。
- 锁外 `load_buffer`（`fread`）装满。
- `finish_reading()`：
  - 等待 `(work_pool.size() + processed_pool.size()) < WORK_PROCESSED_MAX`（总在途背压）。
  - 从空闲池弹出该 buffer，`claimed=false`，置 `seq=next`，`work_pool[seq]=buf`，`notify_all`。
  - 读到 `FINAL` 记 `total_chunks=next+1`；`NODATA` 直接释放该 buffer；置 `read_done=true`，退出。

### 4.2 工作线程 `wait_loaded` / `finish_chunk`

- `wait_loaded(id, seq_next)` 等待 `work_pool.find(seq_next)` 存在，或 `read_done && !worker_pending_locked(id)`；然后 `claim_locked(seq_next)` 返回该 block（仍在工作池中）。
- 工作线程按模式做 AES/HMAC（加密：先 AES 后 HMAC；解密：先 HMAC 后 AES；验证：只 HMAC）。
- `finish_chunk(buffer)`：`work_pool.erase(buffer->seq)`，`processed_pool.push(buffer)`（最小堆按 seq 排序），`notify_all`。

### 4.3 写线程 `run_write`

- `wait_processed_buffer(next)` 等待 `processed_pool.top()->seq == next` 或 `read_done && next == total_chunks`；然后 `claim_processed()` 返回堆顶（peek，不弹出）。
- 锁外 `export_buffer` 写出，`printload` 打印进度（验证模式不写）。
- `finish_writing(buffer)`：`processed_pool.pop()`，`recycle_locked(buffer)`，`notify_all`。

## 5. 回收与清理

`recycle_locked(buf)`（持有 `mtx`）：

- `read_done` 为真：`delete buf` 并 `sweep_idle_locked()` 清空空闲池。
- `read_done` 为假：
  1. 淘汰空闲池前端 `idle_ts` 超过 `IDLE_TIMEOUT_MS` 的空闲 buffer（跳过 `claimed` 的 buffer）；
  2. `idle_pool.size() >= IDLE_POOL_MAX` 时 `delete buf`；
  3. 否则置 `idle_ts=steady_us()` 并 `push_back` 归还空闲池。

## 6. 有序性与死锁安全

- **有序**：读线程分配的 `seq` 单调递增；写线程严格按 `seq` 递增消费。
- **有界背压**：`work_pool + processed_pool < WORK_PROCESSED_MAX`，内存上界 ≈ (总在途 + 空闲池) × 16MB。
- **无死锁**：流水线为 `读 → 工作 → 写` 单向 DAG。

## 7. 调度编排与回调

`multicry_master` 内部持有四类回调，由编排层注入：

| 回调 | setter | 消费线程 | 作用 |
| --- | --- | --- | --- |
| `hmac_func[i]` | `set_hmac_func(fn, id)` | 工作线程 i | 对块数据计算叶 HMAC |
| `mt_func` | `set_mt_func(fn)` | 工作线程 | 把叶 HMAC 合并进 Merkle 树 |
| `printload` | `set_print_load(fn)` | 写线程 | 打印进度 |
| `aes_func[i]` | `set_aes_mode(fn, id)` | 工作线程 i | 对 16 字节块执行 AES |

验证模式 `aes_func[i]` 注入 `nullptr`。

`run_multicry(threads_num, mode)`：

- 启动写线程与 N 个工作线程；`run_read` 复用当前调用线程。
- 汇合顺序：写线程 → 工作线程。

## 8. 本次改进点（相对旧版）

1. 取消独立 HASH 线程，HMAC 由各工作线程就地计算，并配合 Merkle 树合并叶 HMAC。
2. 缓冲池由两池扩展为三池（空闲池/工作池/已处理池），工作池与已处理池共用 `WORK_PROCESSED_MAX`。
3. 读线程认领 buffer 后仍留在空闲池中直到 `fread` 完成，空闲池大小能真实反映读线程占用的 buffer。
4. 调度日志增加 `processed`/`live` 列与 `_PRE` 前后记录。
