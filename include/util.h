#ifndef UTL
#define UTL

#include "./util/base64.h"
#include "./util/buffer.h"
#include "./util/ioprint.h"
#include "./util/struct.h"
#include "./util/tab.h"

typedef unsigned char u8_t;
typedef unsigned short u16_t;
typedef unsigned int u32_t;
typedef unsigned long long u64_t;

//转换subbyte
#define sub_bytes(x) s_box[x]
//还原subbyte
#define r_sub_bytes(x) rs_box[x]
//将一个十六进制位转化为base64编码
#define turn_base64(in) b64_tab[in]
//将base64编码转化为一个十六进制位
#define turn_hex(in) hex_tab[in]
//将x循环左移i位
#define lrot(x, i) (((x) << (i)) | ((x) >> (32 - i)))
//将x循环右移i位
#define rrot(x, i) (((x) >> (i)) | ((x) << (32 - i)))
//对byteint每字节赋值
#define setbytes(t, b0, b1, b2, b3)                                            \
  t = ((u32_t)b0) | ((u32_t)b1 << 8) | ((u32_t)b2 << 16) | ((u32_t)b3 << 24)
//在GF(255)上执行乘法
#define Gmul(u, v) ((v) ? Alogtable[(u) + Logtable[(v)]] : 0)
//在GF(255)上执行加法
#define GMlineA(n0, n1, n2, n3)                                                \
  (Gmul(n0, (u8_t)(g0)) ^ Gmul(n1, (u8_t)(g1)) ^ Gmul(n2, (u8_t)(g2)) ^        \
   Gmul(n3, (u8_t)(g3)))
//魔数
constexpr auto Magic_Num = 0xA5C3A500C3A5C3;
//线程数
constexpr auto THREADS_NUM = 4;
//最大线程数
constexpr auto MAX_THREADS = 16;

#define COND_WAIT                                                              \
  std::unique_lock<std::mutex> locker(filelock);                               \
  while (turn != id)                                                           \
    cond.wait(locker);

#define COND_RELEASE                                                           \
  turn = (turn + 1) % size;                                                    \
  cond.notify_all();                                                           \
  locker.unlock();

#endif