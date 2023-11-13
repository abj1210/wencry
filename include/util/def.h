#ifndef DEF
#define DEF

#define sub_bytes(x) s_box[x]
#define r_sub_bytes(x) rs_box[x]
#define lrot(x, i) (((x) << (i)) | ((x) >> (32 - i)))
#define rrot(x, i) (((x) >> (i)) | ((x) << (32 - i)))
#define Gidx(u, v) (Logtable[(u)] + Logtable[(v)])
#define Gmul(idx, v) ((v) ? Alogtable[mod255(idx)] : 0)
#define mod255(x) ((x & 255) + (x >> 8))
#define GMline Gmul(idx0, b0) ^ Gmul(idx1, b1) ^ Gmul(idx2, b2) ^ Gmul(idx3, b3)
#define GIline(n0, n1, n2, n3)                                                 \
  idx0 = Gidx(n0, b0), idx1 = Gidx(n1, b1), idx2 = Gidx(n2, b2),               \
  idx3 = Gidx(n3, b3)

//#define NUM_THREADS 4
//#define MULTI_ENABLE

#define HASH0 0x67452301
#define HASH1 0xEFCDAB89
#define HASH2 0x98BADCFE
#define HASH3 0x10325476
#define HASH4 0xC3D2E1F0

#endif