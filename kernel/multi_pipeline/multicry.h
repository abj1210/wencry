#ifndef MUL
#define MUL
#include "multi_buffergroup.h"
#include <stdio.h>
#include <thread>
#include <functional>
typedef unsigned char u8_t;
/*
multicry_master:多线程调度器
run_multicry 按流水线模式启动线程:加密/解密启动工作线程+写线程+HASH线程,
验证仅启动HASH线程(不AES不写),配合 buffergroup 的"读--HASH--AES--写"统一流水线。
*/
class multicry_master
{
public:
  static const u8_t THREAD_MAX = 16;

private:
  FILE *fin, *fout;                        // 输入/输出文件
  std::thread threads[THREAD_MAX];         // 工作线程句柄数组
  std::function<void(u8_t *)> aes_func[THREAD_MAX];    // 各工作线程AES加密的回调
  std::function<void(const u8_t *, size_t)> hash_feed; // HASH线程喂入HMAC的回调
  std::function<void(std::string, size_t)> printload;  // 进度打印回调
  
  void multiruncrypt_file(u8_t id);        // 工作线程
  void run_hash();                         // HASH线程(按序消费密文喂HMAC)
  void run_read(pipe_mode mode);           // 读线程
  void run_write(pipe_mode mode);          // 写线程

public:
  /* multicry_master:构造,绑定输入/输出文件并初始化各回调为空 */
  multicry_master(FILE * fin, FILE * fout): 
  fin(fin), fout(fout),
  hash_feed(nullptr), printload(nullptr){
    for(int i = 0; i < THREAD_MAX ; i++)
      aes_func[i] = nullptr;
  };
  /* set_hash_feed:设置 HASH 线程喂入 HMAC 的回调 */
  void set_hash_feed(const std::function<void(const u8_t *, size_t)> &feed) { hash_feed = feed; };
  /* set_print_load:设置进度打印回调 */
  void set_print_load(const std::function<void(std::string, size_t)> &print){printload = print; };
  /* set_aes_mode:设置指定工作线程的 AES 回调 */
  void set_aes_mode(const std::function<void(u8_t *)> &func,const u8_t id){aes_func[id] = func;}
  /* run_multicry:按流水线模式启动读/HASH/AES/写线程(见 multicry.cpp) */
  void run_multicry(u8_t threads_num, pipe_mode mode);
};

#endif
