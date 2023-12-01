#ifndef UTL
#define UTL

#include "./util/buffer.h"
#include "./util/struct.h"
#include "./util/tab.h"

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
  t = ((unsigned int)b0) | ((unsigned int)b1 << 8) |                           \
      ((unsigned int)b2 << 16) | ((unsigned int)b3 << 24)
//在GF(255)上执行乘法
#define Gmul(u, v) ((v) ? Alogtable[(u) + Logtable[(v)]] : 0)
//在GF(255)上执行加法
#define GMlineA(n0, n1, n2, n3)                                                \
  (Gmul(n0, (unsigned char)(g0)) ^ Gmul(n1, (unsigned char)(g1)) ^             \
   Gmul(n2, (unsigned char)(g2)) ^ Gmul(n3, (unsigned char)(g3)))
//魔数
#define Magic_Num 0xA5C3A500C3A5C3

//是否开启多线程模式
//!!!请勿去掉该宏!!!
#define MULTI_ENABLE
//线程数
#define THREADS_NUM 4
//最大线程数
#define MAX_THREADS 16

#endif