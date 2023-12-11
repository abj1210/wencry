#ifndef MUL
#define MUL
#include <stdio.h>
typedef unsigned char u8_t;
//线程数

constexpr auto THREADS_NUM = 4;
//创建线程

#define CREATE_THREAD(type) \
{\
    aes[i] = new type##aes(key, r_hash);\
    threads[i] = std::thread(multiruncrypt_file, i, &tail, aes[i], &bg);\
}
//等待线程

#define JOIN_THREAD \
{\
    threads[i].join();\
    delete aes[i];\
}
void multienc_master(FILE *fp, FILE *out, u8_t *key, const u8_t *r_hash,
                     u8_t &tail);
void multidec_master(FILE *fp, FILE *out, u8_t *key, const u8_t *r_hash,
                     u8_t tail);

#endif