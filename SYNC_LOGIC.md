# 缓冲池与多线程调度同步逻辑说明

本文档描述多线程加解密流水线：调度层 `MulticryMaster` 与缓冲池层 `BufferGroup` 的协作过程与同步逻辑。

- 编排层 `kernel/cry.cpp`：`RunCrypt` 通过 `prepareCrypter` 统一装配流水线。
- 调度层 `kernel/multi_pipeline/multicry.h/.cpp`：`MulticryMaster` 持有输入/输出文件与回调，负责线程创建与汇合。
- 缓冲池层 `kernel/multi_pipeline/buffergroup/multi_buffergroup.h/.cpp`：维护空闲池/工作池/已处理池与全局序号，提供加锁原语。

## 1. 设计目标

- 缓冲从「一次性固定分配」改为「运行时按需动态分配」。
- `BufferGroup` 维护三个缓冲池：空闲池 `idle_pool`、工作池 `work_pool`、已处理池 `processed_pool`。
- 工作池与已处理池共用总在途上限 `WORK_PROCESSED_MAX`。
- 每个 buffer 只保留统一全局序号 `seq`，序号既决定写出顺序，又通过 `seq % total_threads` 推导归属线程。
- HMAC 由各工作线程就地计算（无独立 HASH 线程）。

## 2. 数据流

读线程从空闲池认领 buffer（空则 `new`，认领时即移出空闲池），`fread` 装满后由 `finishLoading` 移入工作池；工作线程按 `seq % total_threads` 领取本线程名下的块，AES/HMAC 完成后移入已处理池；写线程按 `seq` 递增从已处理池取出写出，并把 buffer 归还空闲池（读取结束后直接释放）。`fread` / `fwrite` 均在锁外执行。

## 3. 各模式流转

| 模式 | 流转 |
| --- | --- |
| 加密 | `EMPTY → LOADED → (工作线程 AES+HMAC) → PROCESSED → 写出 → EMPTY` |
| 解密 | `EMPTY → LOADED → (工作线程 HMAC+AES) → PROCESSED → 写出 → EMPTY` |
| 验证 | `EMPTY → LOADED → (工作线程 HMAC) → PROCESSED → 回收 → EMPTY` |

## 4. 同步原语

- `mtxwp` + `cvwp`：保护 `work_pool`、`processed_pool`、`total_chunks`、`read_done`，所有池状态变更持锁执行并以 `cvwp.notify_all()` 唤醒等待方，等待方用谓词判定。
- `mtxi`：单独保护 `idle_pool`。两级锁互不嵌套，不存在锁序反转。
- `total_chunks` / `read_done` 为原子量：写线程回收路径（`sendIdlePool`）与谓词判断可无锁读取，同时避免数据竞争。

### 4.1 读线程 `runReader`

- `recvIdlePool(seq)`：取空闲 buffer（空闲池为空则 `new IoBuffer`），置 `seq` 后返回（此时已移出空闲池）。
- 锁外 `loadBuffer(fin, ispadding)` 执行 `fread`，返回 `FULL` / `FINAL` / `NODATA`。
- `finishLoading(buf, ls, next)`（同一把 `mtxwp` 内完成，避免「已宣布读取结束、末块却未进工作池」的空窗）：
  - 先按 `work_pool.size() + processed_pool.size() < WORK_PROCESSED_MAX` 做背压等待；
  - `NODATA`：不产生块，直接释放该 buffer（`total_chunks` 保持不变）；
  - 其他：写入 `work_pool[next]`，并置 `total_chunks = next + 1`；
  - `ls != FULL` 时置 `read_done = true`；
  - 返回 `ls != FULL` 供读线程判定是否退出。

### 4.2 工作线程 `recvWorkPool` / `sendProcessedPool`

- `recvWorkPool(next)` 等待 `work_pool` 中存在序号为 `next` 的块；当 `read_done` 且「`next` 已越界或工作池已空」时返回 `NULL` 哨兵表示本线程已无任务。
- 工作线程按模式做 AES/HMAC（加密：先 AES 后 HMAC；解密：先 HMAC 后 AES；验证：只 HMAC）。
- `sendProcessedPool(buf)` 把该块移入已处理池，并返回本线程下一个期望序号 `seq + total_threads`。

### 4.3 写线程 `recvProcessedPool` / `sendIdlePool`

- `recvProcessedPool(next)` 只取走堆顶且序号正好等于 `next` 的块，保证输出顺序；当 `read_done` 且 `next ≥ total_chunks` 时返回 `NULL` 哨兵，表示所有块都已写出（绝不触碰空堆）。
- 锁外 `exportBuffer(fout, isfinal, ispadding)` 写出，`printload` 打印进度（验证模式不写）。`isfinal` 由 `getFinalBlock(seq)` 判定（`read_done && seq + 1 == total_chunks`）。
- `sendIdlePool(buf)` 归还 buffer；`read_done` 已置位或空闲池已满时直接释放。

## 5. 回收与清理

`sendIdlePool(buf)`（持有 `mtxi`）：

- `read_done` 为真：`releaseBuffer(buf)` 直接释放（读取结束后不再复用，内存随流水线收敛）。
- 否则空闲池 `size() >= IDLE_POOL_MAX` 时 `releaseBuffer(buf)`；
- 否则 `push_back` 归还空闲池。

内存上界 ≈（在途上限 `WORK_PROCESSED_MAX` + 空闲池上限 `IDLE_POOL_MAX` + 1）× 16MB；`delInstance()` 在流水线线程全部汇合后兜底释放所有池内 buffer。

## 6. 有序性与死锁安全

- **有序**：读线程分配的 `seq` 单调递增；写线程严格按 `seq` 递增消费。
- **有界背压**：`work_pool + processed_pool < WORK_PROCESSED_MAX`，内存上界 ≈ (总在途 + 空闲池) × 16MB。
- **无死锁**：流水线为 `读 → 工作 → 写` 单向 DAG，各线程等待的是下游进展，无环。
- **终止**：读线程 `FINAL`/`NODATA` 置 `read_done`；工作线程与写线程均以 `NULL` 哨兵退出，不依赖「某个池恰好为空」这类会被调度顺序影响的瞬时状态。

## 7. 调度编排与回调

`MulticryMaster` 内部持有四类回调，由编排层注入：

| 回调 | setter | 消费线程 | 作用 |
| --- | --- | --- | --- |
| `hmac_func[i]` | `setHmacCallback(fn, id)` | 工作线程 i | 对块数据计算叶 HMAC |
| `mt_func` | `setMerkleTreeCallback(fn)` | 工作线程 | 把叶 HMAC 合并进 Merkle 树 |
| `printload` | `setProgressCallback(fn)` | 写线程 | 打印进度 |
| `aes_func[i]` | `setAesCallback(fn, id)` | 工作线程 i | 对 16 字节块执行 AES |

验证模式 `aes_func[i]` 注入 `nullptr`。

`runMulticry(threads_num, mode)`：

- 启动写线程与 N 个工作线程；`runReader` 复用当前调用线程。
- 汇合顺序：写线程 → 工作线程。

## 8. 改进点（相对更早的版本）

1. 取消独立 HASH 线程，HMAC 由各工作线程就地计算，并配合 Merkle 树合并叶 HMAC。
2. 缓冲池由两池扩展为三池（空闲池/工作池/已处理池），工作池与已处理池共用 `WORK_PROCESSED_MAX`。
3. 统一全局序号 `seq` 取代原 `threadid`/`seq` 双标志；工作线程只领取自己名下的块。
4. 读线程的「登记块」与「置位读取结束」在同一把锁内完成，工作线程/写线程以统一哨兵退出。
5. 调度日志增加 `processed`/`live` 列与 `_PRE` 前后记录（`LOG_SCHED` 打开时可用 `analyze_sched.py` 分析）。
