#ifndef MUL
#define MUL
#include "aesmode.h"
#include "multi_buffergroup.h"
#include <stdio.h>
#include <thread>
typedef unsigned char u8_t;
/*
多线程加解密抽象类
*/
class multicry_master
{
public:
  const u8_t THREADS_NUM;
  static const u8_t THREAD_MAX = 16;

private:
  std::thread threads[THREAD_MAX];
  FILE *fp, *out;
  bool isenc;

public:
  multicry_master(FILE *fp, FILE *out, u8_t *key, u8_t ctype, u8_t thread_num, u8_t *iv,
                  bool no_echo);
  void run_multicry(buffergroup &iobuffer, Aesmode ** mode);
};
/*
  多线程加解密类工厂
*/
class GetCryMaster
{
  multicry_master *cm;
  FILE *fp, *out;
  u8_t *key, ctype, thread_num;
  bool no_echo;

public:
  GetCryMaster(FILE *fp, FILE *out, u8_t *key, u8_t ctype, u8_t thread_num, 
               bool no_echo) : fp(fp), out(out), key(key), ctype(ctype), thread_num(thread_num), no_echo(no_echo), cm(NULL){};
  ~GetCryMaster() { delete cm; };
  multicry_master *get_multicry_master(u8_t * iv, char mode);
};

#endif