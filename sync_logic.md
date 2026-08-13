# 缓冲池同步逻辑说明

本文档描述 `buffergroup` 重构后的缓冲池工作流程与多线程同步逻辑。
代码位于 `kernel/multi_aes/multi_buffergroup.h` 与 `kernel/multi_aes/multi_buffergroup.cpp`。

## 1. 设计目标

- 缓冲从「一次性固定分配」改为「运行时按需动态分配」。
- `buffergroup` 维护两个缓冲池：**空闲池** `idle_pool` 与**工作池** `work_pool`。
- 两个池均设容量上限；为每个空闲 buffer 记录进入空闲池的时间戳以支持超时释放。
- 删除每个 buffer 的 `threadid`/`seq` 标志，改用统一全局序号 `seq` 保证有序。

## 2. 数据流

```
          ┌─────────────── 空闲池 idle_pool ───────────────┐
          │ (可复用的空 buffer, 容量上限 IDLE_POOL_MAX)     │
          └──────────────┬────────────────────▲────────────┘
                 读线程取(空则 new)          写线程回收(满/超时则释放)
                         │                    │
                         ▼                    │
              ┌───────────────────────────────┴────────────┐
              │              工作池 work_pool               │
              │  (在途 buffer, 键 = 全局序号 seq,            │
              │   容量上限 WORK_POOL_MAX, 满则读线程阻塞)    │
              └──────┬──────────────┬───────────────┬───────┘
                     │HASH按seq消费  │工作线程按        │写线程按seq写出
                     │(喂HMAC)       │seq%N领取AES     │并回收/释放
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
