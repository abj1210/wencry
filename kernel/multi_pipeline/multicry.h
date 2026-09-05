#ifndef MUL
#define MUL
#include "multi_buffergroup.h"
#include <stdio.h>
#include <thread>
#include <functional>
typedef unsigned char u8_t;
/*
MulticryMaster:多线程调度器
runMulticry 按流水线模式启动线程:加密/解密/验证均启动写线程与 N 个工作线程,
读线程复用调用线程;HMAC 由各工作线程就地计算(无独立 HASH 线程)。
*/
class MulticryMaster
{
public:
  static const u8_t THREAD_MAX = 16;

private:
  FILE *fin, *fout;                        // 输入/输出文件
  std::thread threads[THREAD_MAX];         // 工作线程句柄数组
  std::function<void(u8_t *)> aes_func[THREAD_MAX];    // 各工作线程AES加密的回调
  std::function<void(const u8_t *, u8_t *, size_t, size_t)> hmac_func[THREAD_MAX]; // HASH线程喂入HMAC的回调
  std::function<void(const u8_t *, size_t)> mt_func;
  std::function<void(std::string, size_t)> printload;  // 进度打印回调
  size_t written_bytes;                     // 写线程累计实际写出的字节数(解密时用于截断)
  size_t hash_size;

  void runWorker(pipe_mode mode, u8_t id);        // 工作线程
  void runReader(pipe_mode mode);           // 读线程
  void runWriter(pipe_mode mode);          // 写线程

public:
  /* MulticryMaster:构造,绑定输入/输出文件并初始化各回调为空 */
  MulticryMaster(FILE * fin, FILE * fout): 
  fin(fin), fout(fout), printload(nullptr), written_bytes(0), hash_size(0){
    for(int i = 0; i < THREAD_MAX ; i++){
      hmac_func[i] = nullptr;
      aes_func[i] = nullptr;
    }
  };
  /* set_hash_feed:设置 HASH 线程喂入 HMAC 的回调 */
  void setHmacCallback(const std::function<void(const u8_t *, u8_t *, size_t, size_t)> &feed,const u8_t id) { hmac_func[id] = feed; };
  void setMerkleTreeCallback(const std::function<void(const u8_t *, size_t)> &mt){mt_func = mt;};
  /* setProgressCallback:设置进度打印回调 */
  void setProgressCallback(const std::function<void(std::string, size_t)> &print){printload = print; };
  /* setAesCallback:设置指定工作线程的 AES 回调 */
  void setAesCallback(const std::function<void(u8_t *)> &func,const u8_t id){aes_func[id] = func;};
  /* setHashSize:设置对应哈希类型的哈希长度 */
  void setHashSize(size_t hash_size){this->hash_size = hash_size;};
  /* getWrittenBytes:返回写线程累计写出的字节数(解密完成后为明文长度) */
  size_t getWrittenBytes() const { return written_bytes; }
  /* runMulticry:按流水线模式启动读/HASH/AES/写线程(见 multicry.cpp) */
  void runMulticry(u8_t threads_num, pipe_mode mode);
};

#endif
