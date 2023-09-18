#ifndef DEF
#define DEF

#define sub_bytes(x) s_box[x]
#define r_sub_bytes(x) rs_box[x]
#define lrot(x, i) (((x) << (i)) | ((x) >> (32 - i)))
#define rrot(x, i) (((x) >> (i)) | ((x) << (32 - i)))
#define GMul(u, v) ((v) ? Alogtable[mod255(Logtable[(u)] + Logtable[(v)])] : 0)
#define Gidx(u, v) (Logtable[(u)] + Logtable[(v)])
#define Gmul(idx, v) ((v) ? Alogtable[mod255(idx)] : 0)
#define mod255(x) ((x & 255) + (x >> 8))

#define HASH0 0x67452301
#define HASH1 0xEFCDAB89
#define HASH2 0x98BADCFE
#define HASH3 0x10325476
#define HASH4 0xC3D2E1F0

#endif