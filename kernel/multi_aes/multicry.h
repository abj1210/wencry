#ifndef MUL
#define MUL
#include "aesmode.h"
#include "multi_buffergroup.h"
#include <stdio.h>
#include <thread>
typedef unsigned char u8_t;
class multicry_master
{
public:
  const u8_t THREADS_NUM;
  static const u8_t THREAD_MAX = 16;

private:
  buffergroup bg;
  std::thread threads[THREAD_MAX];
  FILE *fp, *out;
  bool isenc;

protected:
  Aesmode *am[THREAD_MAX];

public:
  multicry_master(FILE *fp, FILE *out, u8_t *key, const u8_t *iv, u8_t ctype, u8_t thread_num,
                  bool isenc, bool no_echo);
  ~multicry_master();
  friend void multiruncrypt_file(u8_t id, multicry_master *cm);
  void run_multicry();
  void load_iv(u8_t *iv);
  virtual void process(u8_t id, u8_t *block) = 0;
};

class multienc_master : public multicry_master
{
public:
  multienc_master(FILE *fp, FILE *out, u8_t *key, const u8_t *iv, u8_t ctype, u8_t thread_num, bool no_echo)
      : multicry_master(fp, out, key, iv, ctype, thread_num, true, no_echo){};
  virtual void process(u8_t id, u8_t *block) { am[id]->getencry(block); };
};

class multidec_master : public multicry_master
{
public:
  multidec_master(FILE *fp, FILE *out, u8_t *key, const u8_t *iv, u8_t ctype, u8_t thread_num, bool no_echo)
      : multicry_master(fp, out, key, iv, ctype, thread_num, false, no_echo){};
  virtual void process(u8_t id, u8_t *block) { am[id]->getdecry(block); };
};

class GetCryMaster 
{
  multicry_master *cm;
  FILE *fp, *out;
  u8_t *key, ctype, thread_num;
  const u8_t * iv;
  bool no_echo;
public:
  GetCryMaster(FILE *fp, FILE *out, u8_t *key, const u8_t *iv, u8_t ctype, u8_t thread_num,
              bool no_echo): fp(fp), out(out), key(key), iv(iv), thread_num(thread_num), no_echo(no_echo), cm(NULL){};
  ~GetCryMaster(){delete cm;};
  multicry_master * get_multicry_master(char mode);
};

#endif