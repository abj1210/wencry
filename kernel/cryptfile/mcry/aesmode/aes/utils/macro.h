#ifndef AMAC
#define AMAC
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

#define GMumLine(n0, n1, n2, n3)                                               \
  (Gmul(n0, (u8_t)(g0)) ^ Gmul(n1, (u8_t)(g1)) ^ Gmul(n2, (u8_t)(g2)) ^        \
   Gmul(n3, (u8_t)(g3)))

#endif