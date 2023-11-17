#ifndef DEF
#define DEF
//转换subbyte
#define sub_bytes(x) s_box[x]
//还原subbyte
#define r_sub_bytes(x) rs_box[x]
//将x循环左移i位
#define lrot(x, i) (((x) << (i)) | ((x) >> (32 - i)))
//将x循环右移i位
#define rrot(x, i) (((x) >> (i)) | ((x) << (32 - i)))
//在GF(255)上执行乘法
#define Gmul(u, v) ((v) ? Alogtable[(u) + Logtable[(v)]] : 0)
//在GF(255)上执行加法
#define GMline(n0, n1, n2, n3)                                                 \
  Gmul(n0, b0) ^ Gmul(n1, b1) ^ Gmul(n2, b2) ^ Gmul(n3, b3)

#define HASH0 0x67452301
#define HASH1 0xEFCDAB89
#define HASH2 0x98BADCFE
#define HASH3 0x10325476
#define HASH4 0xC3D2E1F0

#endif