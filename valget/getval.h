#ifndef GETV
#define GETV
#include <stdio.h>
#include <string>
typedef unsigned char u8_t;
/*
vpak:参数包
fp:输入文件
out:输出文件
key:初始密钥
r_buf:随机缓冲数组
mode:模式(加密/解密)
*/
typedef union
{
  struct
  {
    FILE *fp, *out;
    u8_t *key;
    u8_t r_buf[256];
    size_t size;
    char mode, ctype, htype;
    bool no_echo;
  };
  u8_t buf[512];
} vpak_t;

void printkey(u8_t *key);
std::string get_ctypelist();
std::string get_htypelist();
bool check_ctype(int ctype_num);
bool check_htype(int htype_num);
std::string get_cname(int ctype_num);
std::string get_hname(int htype_num);
void strlog(std::string s1, std::string s2, char fill = ' ');
u8_t *getRandomKey();
u8_t *get_v_mod1();
u8_t *get_v_opt(int argc, char *argv[]);
void version();
std::string verstring();
void help();
#endif