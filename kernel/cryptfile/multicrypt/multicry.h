#ifndef MUL
#define MUL
#include "aes.h"
#include "multi_buffergroup.h"
#include <stdio.h>
#include <thread>
typedef unsigned char u8_t;
class multicry_master {
public:
  static const auto THREADS_NUM = 4;

private:
  u8_t tail;
  buffergroup bg;
  std::thread threads[THREADS_NUM];

protected:
  aeshandle *aes[THREADS_NUM];

public:
  multicry_master(FILE *fp, FILE *out, const u8_t tail)
      : tail(tail), bg(THREADS_NUM, fp, out){};
  ~multicry_master();
  friend void multiruncrypt_file(u8_t id, multicry_master *cm);
  u8_t run_multicry();
};
class multienc_master : public multicry_master {
public:
  multienc_master(FILE *fp, FILE *out, u8_t *key, const u8_t *r_hash,
                  const u8_t tail);
};
class multidec_master : public multicry_master {
public:
  multidec_master(FILE *fp, FILE *out, u8_t *key, const u8_t *r_hash,
                  const u8_t tail);
};

#endif