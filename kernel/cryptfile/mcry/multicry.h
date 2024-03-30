#ifndef MUL
#define MUL
#include "aesmode.h"
#include "multi_buffergroup.h"
#include <stdio.h>
#include <thread>
typedef unsigned char u8_t;
class multicry_master {
public:
  const u8_t THREADS_NUM;
  static const u8_t THREAD_MAX = 16;
private:
  buffergroup bg;
  std::thread threads[THREAD_MAX];

protected:
  Aesmode *am[THREAD_MAX];

public:
  multicry_master(FILE *fp, FILE *out, u8_t *key, const u8_t *iv, u8_t ctype, u8_t thread_num, 
                  bool isenc, bool no_echo): THREADS_NUM(thread_num), bg(thread_num, fp, out, isenc, no_echo) {
    for (int i = 0; i < THREADS_NUM; ++i)
      am[i] = selectCryptMode(key, iv + (20 * i), ctype);
  };
  ~multicry_master(){
    for (int i = 0; i < THREADS_NUM; ++i)
          delete am[i];
  }
  friend void multiruncrypt_file(u8_t id, multicry_master *cm);
  void run_multicry();
  virtual void process(u8_t id, u8_t *block) = 0;
};
class multienc_master : public multicry_master {
public:
  multienc_master(FILE *fp, FILE *out, u8_t *key, const u8_t *iv, u8_t ctype, u8_t thread_num, bool no_echo)
      : multicry_master(fp, out, key, iv, ctype, thread_num , true, no_echo){};
  virtual void process(u8_t id, u8_t *block) { am[id]->getencry(block); };
};
class multidec_master : public multicry_master {
public:
  multidec_master(FILE *fp, FILE *out, u8_t *key, const u8_t *iv, u8_t ctype, u8_t thread_num, bool no_echo)
      : multicry_master(fp, out, key, iv, ctype, thread_num , false, no_echo){};
  virtual void process(u8_t id, u8_t *block) { am[id]->getdecry(block); };
};

#endif