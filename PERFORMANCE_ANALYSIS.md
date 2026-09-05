# Wencry 性能分析说明

本文汇总 Wencry 项目的 IO 效率与多线程调度分析结论、已实施的优化、性能分析工具的使用方法，以及关键实测数据。

## 1. 项目与流水线概述

Wencry 是一个 C++17 实现的 AES-128 文件加解密工具：

- AES-NI 硬件加密，支持 ECB / CBC / CTR / CFB / OFB 五种模式。
- HMAC 完整性校验，支持 SHA1-NI / SHA256-NI / MD5。
- 统一的多线程流水线：读线程 → N 个工作线程（AES + HMAC）→ 写线程。
- 单块 16 MB（IoBuffer），工作池+已处理池共用总在途上限 WORK_PROCESSED_MAX=12，空闲池容量 IDLE_POOL_MAX=4。
- 加密 / 解密 / 验证三种模式共用同一套流水线。

核心 IO 路径：

- 加密：读明文 → 原地 AES → 写密文；HMAC 读内存中的密文增量计算，不回读。
- 解密：读密文 → 工作线程先算 HMAC → 原地 AES → 写明文。
- 验证：读密文 → 工作线程只算 HMAC，不 AES、不写文件。

## 2. 性能分析工具

### 2.1 调度日志（编译期开关 LOG_SCHED）

开启后每次运行会把线程时间线与缓冲区生命周期写入 sched_log.csv。

构建方式：

```bat
cmake -S . -B build_log -G "Visual Studio 18 2026" -A x64 -DBUILD_TEST=OFF -DLOG_SCHED=ON
cmake --build build_log --config Release
```

日志列：us,role,event,id,seq,state,work,idle,processed,live

事件类型：

| 事件 | 含义 |
|---|---|
| RUN_START / RUN_END | 一次运行开始/结束，state 记录 模式:线程数 |
| BUF_NEW / BUF_DELETE | 缓冲区生成 / 销毁（SchedLog 据此维护 live 计数） |
| BUF_NEW_PRE / BUF_DELETE_AFTER | 缓冲申请前 / 释放后的池状态记录 |
| POP_IDLE | 读线程取用空闲缓冲（含 POP_IDLE_PRE） |
| LOADED / POP_WORK / PROCESSED / POP_PROCESSED / EMPTY | 三池迁移（各含 _PRE 前置记录） |
| READ_DONE / SWEEP | 读取完成 / 空闲池被清空 |
| LOAD_BEGIN / LOAD_END | 读线程装载一块，seq 为块号 |
| AES_BEGIN / AES_END | 工作线程 AES 一块，id 为工作线程号 |
| HASH_BEGIN / HASH_END | 工作线程 HMAC 一块，seq 为块号 |
| WRITE_BEGIN / WRITE_END | 写线程写出一块，seq 为块号 |

其中 `work/idle/processed` 为三个池当前大小，`live` 为当前存活 buffer 数（由 BUF_NEW/BUF_DELETE 内部计数）。

### 2.2 分析脚本 analyze_sched.py

集成“生成输入 → 运行加密/解密/验证 → 收集日志 → 分析 → 生成 HTML 报告”的完整流程：

```bat
python analyze_sched.py --out sched_report
```

参数：--exe（Wencry.exe 路径）、--sizes（如 32,200,512）、--key、--out。

报告包含：

- 三种模式吞吐对比柱状图（纵轴少量刻度、柱子标注具体值）。
- 按文件大小分组的工作池/空闲池折线图、线程占用率条形图、线程忙/闲甘特图。
- 指标表（耗时、吞吐、池峰值、缓冲区创建/复用等）。

脚本仅依赖标准库，图表以内嵌 SVG 生成，无需 matplotlib / pandas。

## 3. IO 效率分析

### 3.1 已经做到接近最优的部分

- 字节层面 IO 最小：明文/密文各只读一遍、写一遍，HMAC 不再回读第二遍。
- 16 MB 大块 + 二进制模式，避免 CRLF 转换和过多系统调用。
- fread / fwrite 在锁外执行，IO 与 AES / HASH 重叠。

### 3.2 已实施的 IO 优化

| 优化 | 做法 | 说明 |
|---|---|---|
| 输出预分配 | SetFilePointerEx + SetEndOfFile（Windows）/ ftruncate（Linux） | 避免边写边扩展的 extent 碎片；不能用 _chsize_s，它会同步写零，实测造成约 13 倍回退 |
| 顺序访问提示 | Windows _O_SEQUENTIAL（FILE_FLAG_SEQUENTIAL_SCAN）/ Linux posix_fadvise | 改善预读与缓存淘汰 |
| wb+ → wb | 输出流改为纯写模式 | 去掉更新流不必要的读写状态检查 |

注意：在快速 NVMe 且数据整体落入页缓存时，上述三项对吞吐无显著提升（实测 512 MiB 加密基线约 1617 MiB/s，优化后约 1630 MiB/s，属噪声范围）；它们的价值主要体现在机械盘、网络盘、WSL 9p 挂载、冷缓存等场景。

### 3.3 关于内存映射文件（mmap）

结论：mmap 对本项目性价比不高。它只能省掉“读路径上内核页缓存 → 用户缓冲的一次拷贝”，而这不是当前瓶颈；并且与本项目的“16 MB 缓冲池 + 原地 AES + IV 链连续”架构冲突。唯一较适合的场景是只读的验证模式。

## 4. 缓冲池容量分析

WORK_PROCESSED_MAX（工作池+已处理池总在途 buffer）与 IDLE_POOL_MAX（空闲池，可复用 buffer）现已可通过 CMake 覆盖：

```bat
cmake ... -DWORK_PROCESSED_MAX=16 -DIDLE_POOL_MAX=4 ...
```

512 MiB CBC+sha1 加密实测（MiB/s）：

> 下表沿用旧版 `WORK_POOL_MAX` / `PROCESSED_POOL_MAX` 的 W/P 记号，当前已合并为 `WORK_PROCESSED_MAX`（原 W+P 之和）。

| 配置 | 加密 MiB/s | 结论 |
|---|---|---|
| W2_I1 | 847 | 太小，工作线程空等，慢约 47% |
| W4_I2 | 1402 | 仍偏小，慢约 10% |
| W8_I4（旧默认） | 1555 | 接近最优 |
| W16_I4 | 1578 | 边际 +1.5%，基本持平 |
| W32_I8 | 1507 | 无提升，略降（工作集增大挤占缓存） |
| W8_I1 | 1534 | 与 W8_I4 持平，说明空闲池=1 已够 |

结论：

- WORK_PROCESSED_MAX=16（原 W8+P8）是拐点，再增大收益递减，过大反而因内存/缓存压力略降（当前 CMake 默认 12，稍低于该拐点）。
- IDLE_POOL_MAX 影响可忽略：平衡负载下空闲池峰值只有 1，设 1~2 即可；只有“写明显快于读”的突发场景才需要更大空闲池。
- 内存代价：每个 buffer 16 MB；按当前默认（总在途 12 + 空闲 4）峰值约 256 MB。

## 5. 哈希线程效率分析

### 5.1 现象

默认 SHA1 时，工作线程内的 HMAC 计算几乎占满一个核心，SHA1-NI 吞吐约 2 GB/s，是加密路径的关键瓶颈（接近 SHA1-NI 硬件吞吐上限）。

### 5.2 已尝试的优化及结论

| 优化 | 结果 |
|---|---|
| 去掉 feedHash 的逐 64 字节 memcpy，整块直接喂 SHA-NI | 正确，但无吞吐提升（SHA-NI 计算占主导，memcpy 只占极小比例） |
| 缓存块变换函数指针，消除每块虚调用 | 正确，但无吞吐提升（函数指针调用仍是间接调用，与虚调用本质相同；A/B 实测 308ms vs 306ms，噪声内） |

### 5.3 根本原因与进一步方向

- SHA1-NI 单块约 30 ns，是主要成本；HMAC 是严格顺序依赖，无法像 AES 那样多线程并行。
- 真正还能挤出几个百分点的是把块变换函数内联进 feedHash 多块循环（状态常驻寄存器、去掉调用/返回），需要 MSVC /GL /LTCG（LTO）或把 sha1_ni_block 移到头文件 inline。
- 要显著突破 2 GB/s，只能换支持并行树形哈希的算法（如 BLAKE3），但那会破坏 .wenc 文件格式与 HMAC 兼容性，不建议轻动。

## 6. 三种模式对比

不指定 cmode（默认 CBC）时，512 MiB 实测：

| 模式 | 耗时 | 吞吐 MiB/s | 说明 |
|---|---|---|---|
| 加密 | 0.314s | 1631 | 读明文 + 写密文两遍 IO |
| 解密 | 0.306s | 1676 | 读密文 + 写明文两遍 IO，HMAC 融合进读取 |
| 验证 | 0.301s | 1703 | 只读密文 + 算 HMAC，单遍 IO，最快 |

结论：验证最快；解密略快于加密；吞吐随文件增大而上升。

## 7. 关键实测数据附录

- 512 MiB 加密（页缓存内）：基线约 1617 MiB/s，优化后约 1630 MiB/s。
- 工作线程 HMAC（512 MiB、33 块）：忙时约 274–308 ms（随环境波动），吞吐约 1.8–2.0 GB/s，占用率约 99.8%。
- 空闲池：平衡负载下峰值 1、均值 0.08–0.14；小文件（≤ 约 128 MB）恒为 0。
- 工作池+已处理池总在途：200 MiB 与 512 MiB 时峰值均为 8（WORK_PROCESSED_MAX 背压生效）。
