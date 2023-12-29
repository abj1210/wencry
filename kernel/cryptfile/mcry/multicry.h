#ifndef MUL
#define MUL
#include "aesmode.h"
#include "multi_buffergroup.h"
#include <stdio.h>
#include <thread>
typedef unsigned char u8_t;
class multicry_master {
public:
  static const auto THREADS_NUM = 4;

private:
  buffergroup bg;
  std::thread threads[THREADS_NUM];

protected:
  Aesmode *am[THREADS_NUM];

public:
  multicry_master(FILE *fp, FILE *out, u8_t *key, const u8_t *iv, u8_t ctype,
                  bool isenc);
  ~multicry_master();
  friend void multiruncrypt_file(u8_t id, multicry_master *cm);
  void run_multicry();
  virtual void process(u8_t id, u8_t *block) = 0;
};
class multienc_master : public multicry_master {
public:
  multienc_master(FILE *fp, FILE *out, u8_t *key, const u8_t *iv, u8_t ctype)
      : multicry_master(fp, out, key, iv, ctype, true){};
  virtual void process(u8_t id, u8_t *block) { am[id]->getencry(block); };
};
class multidec_master : public multicry_master {
public:
  multidec_master(FILE *fp, FILE *out, u8_t *key, const u8_t *iv, u8_t ctype)
      : multicry_master(fp, out, key, iv, ctype, false){};
  virtual void process(u8_t id, u8_t *block) { am[id]->getdecry(block); };
};

#endif