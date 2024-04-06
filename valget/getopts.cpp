#include "getval.h"
#include "base64.h"
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/*################################
  全局变量
################################*/
/*
长选项设置
*/
const struct option longOpts[] = {
    {"encode", no_argument, NULL, 'e'},
    {"decode", no_argument, NULL, 'd'},
    {"verify", no_argument, NULL, 'v'},
    {"version", no_argument, NULL, 'V'},
    {"help", no_argument, NULL, 'h'},
    {"input", required_argument, NULL, 'i'},
    {"output", required_argument, NULL, 'o'},
    {"key", required_argument, NULL, 'k'},
    {"mode", required_argument, NULL, 'm'},
    {"no_echo", no_argument, NULL, 'n'},
    {0, 0, 0, 0}};
/*
短选项设置
*/
const char shortOpts[] = "edvVhni:o:k:m:";
char fout[128];
/*################################
  辅助函数
################################*/
/*
getArgsKey:从参数中获取密钥
arg:参数
return:获取的密钥
*/
static u8_t *getArgsKey(const char *arg)
{
    u8_t *keyout = new u8_t[16];
    base64_to_hex((const u8_t *)arg, 24, keyout);
    return keyout;
}
/*
getRandomBuffer:获取随机的缓冲数组
r_buf:缓冲数组地址
*/
static void getRandomBuffer(u8_t *r_buf)
{
    for (int i = 0; i < 256; ++i)
        r_buf[i] = rand();
}
/*
printCryptMode:打印AES模式
mode:模式
*/
static void printCryptMode(u8_t mode)
{
    fprintf(stderr, "Using Crypt mode :");
    switch (mode)
    {
    case 0:
        fprintf(stderr, "ECB\n");
        break;
    case 1:
        fprintf(stderr, "CBC\n");
        break;
    case 2:
        fprintf(stderr, "CTR\n");
        break;
    case 3:
        fprintf(stderr, "CFB\n");
        break;
    case 4:
        fprintf(stderr, "OFB\n");
        break;
    default:
        fprintf(stderr, "Unknown\n");
        break;
    }
}
/*
parseOpts:解析选项
c:选项字符
res:参数包指针
return:是否解析成功
*/
bool parseOpts(char c, vpak_t *res)
{
    int tnum;
    switch (c)
    {
    case 'e':
        if (res->mode == 'u')
            res->mode = 'e';
        else
        {
            fprintf(stderr, "Only one mode can be specified\n");
            return false;
        }
        break;
    case 'd':
        if (res->mode == 'u')
            res->mode = 'd';
        else
        {
            fprintf(stderr, "Only one mode can be specified\n");
            return false;
        }
        break;
    case 'v':
        if (res->mode == 'u')
            res->mode = 'v';
        else
        {
            fprintf(stderr, "Only one mode can be specified\n");
            return false;
        }
        break;
    case 'i':
        res->fp = fopen(optarg, "rb");
        sprintf(fout, "%s.wenc", optarg);
        if (res->fp == NULL)
        {
            fprintf(stderr, "Could not open file %s\n", optarg);
            return false;
        }
        break;
    case 'o':
        res->out = fopen(optarg, "wb+");
        if (res->out == NULL)
        {
            fprintf(stderr, "Could not open file %s\n", optarg);
            return true;
        }
        break;
    case 'k':
        res->key = getArgsKey(optarg);
        break;
    case 'n':
        res->no_echo = true;
        break;
    case 'm':
        if (res->ctype == 100)
        {
            res->ctype = atoi(optarg);
            printCryptMode(res->ctype);
        }
        else
        {
            fprintf(stderr, "Only one ctype can be specified\n");
            return false;
        }
        break;
    case 'V':
        if (res->mode == 'u')
            res->mode = 'V';
        else
        {
            fprintf(stderr, "Only one mode can be specified\n");
            return false;
        }
        break;

    case 'h':
        if (res->mode == 'u')
            res->mode = 'h';
        else
        {
            fprintf(stderr, "Only one mode can be specified\n");
            return false;
        }

        break;
    default:
        fprintf(stderr, "Unknown option\n");
        return false;
    }
    return true;
}
/*################################
  接口函数
################################*/
/*
get_v_opt:解析命令行参数
argc:命令行参数个数
argv:命令行参数数组
return:vpak_t结构体指针x
*/
u8_t *get_v_opt(int argc, char *argv[])
{
    srand((unsigned)time(NULL));
    memset(fout, 0, sizeof(fout));
    int option_index = 0;
    optind = 1;
    vpak_t *res = new vpak_t;
    res->mode = 'u';
    res->ctype = 100;
    res->no_echo = false;
    res->fp = NULL;
    res->out = NULL;
    res->key = NULL;
    while (true)
    {
        char c = getopt_long(argc, argv, shortOpts, longOpts, &option_index);
        if (c == -1)
            break;
        if (!parseOpts(c, res))
        {
            delete res;
            return NULL;
        }
    }
    if (res->mode == 'u')
    {
        fprintf(stderr, "Wrong Mode %c\n", res->mode);
        delete res;
        return NULL;
    }
    else if (res->mode == 'e' || res->mode == 'd' || res->mode == 'v')
    {
        if (res->ctype == 100)
        {
            fprintf(stderr, "Using ECB mode\n");
            res->ctype = 0;
        }
        else if (res->ctype < 0 || res->ctype > 4)
        {
            fprintf(stderr, "Wrong ctype\n");
            delete res;
            return NULL;
        }
        if (res->key == NULL)
        {
            fprintf(stderr, "Using random key\n");
            res->key = getRandomKey();
        }
        if (res->fp == NULL)
        {
            fprintf(stderr, "No file specified\n");
            delete res;
            return NULL;
        }
        if (res->out == NULL)
        {
            fprintf(stderr, "Using default output file name\n");
            res->out = fopen(fout, "wb+");
        }
        getRandomBuffer(res->r_buf);
        printkey(res->key);
    }
    return res->buf;
}