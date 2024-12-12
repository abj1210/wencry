#include "getval.h"
#include "base64.h"
#include <filesystem>
#include <iostream>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#ifdef OPT_ON

#include <unistd.h>
#include <getopt.h>

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
    {"cmode", required_argument, NULL, 1},
    {"hmode", required_argument, NULL, 2},
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
    std::string cm = "Crypt mode :";
    std::string cry = get_cname(mode);
    strlog(cm, cry);
}
/*
printCryptMode:打印Hash模式
mode:模式
*/
static void printHashMode(u8_t mode)
{
    std::string hm = "Hash mode :";
    std::string hash = get_hname(mode);
    strlog(hm, hash);
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
    size_t fsize = 0;
    switch (c)
    {
    case 'e':
        if (res->mode == 'u')
            res->mode = 'e';
        else
        {
            strlog("Error :", "Only one mode can be specified");
            return false;
        }
        break;
    case 'd':
        if (res->mode == 'u')
            res->mode = 'd';
        else
        {
            strlog("Error :", "Only one mode can be specified");
            return false;
        }
        break;
    case 'v':
        if (res->mode == 'u')
            res->mode = 'v';
        else
        {
            strlog("Error :", "Only one mode can be specified");
            return false;
        }
        break;
    case 'i':
        res->fp = fopen(optarg, "rb");
        sprintf(fout, "%s.wenc", optarg);
        try
        {
            auto fileSize = std::filesystem::file_size(optarg);
            fsize = fileSize;
            strlog("File size: ", std::to_string(((double)fileSize) / ((double)(1024 * 1024))) + "MB");
        }
        catch (std::filesystem::filesystem_error &e)
        {
            std::cerr << "Error: " << e.what() << std::endl;
        }
        if (res->fp == NULL)
        {
            strlog("Error :", "Could not open file " + std::string(optarg));
            return false;
        }
        res->size = fsize;
        break;
    case 'o':
        res->out = fopen(optarg, "wb+");
        if (res->out == NULL)
        {
            strlog("Error :", "Could not open file " + std::string(optarg));
            return false;
        }
        break;
    case 'k':
        if (is_valid_b64((unsigned char *)optarg, strlen(optarg)))
        {
            res->key = getArgsKey(optarg);
            strlog("Key :", "Using specific key");
        }
        else
        {
            strlog("Error :", "Invalid base64 key");
            return false;
        }
        break;
    case 'n':
        res->no_echo = true;
        break;
    case 1:
        if (res->ctype == -1)
        {
            res->ctype = atoi(optarg);
            printCryptMode(res->ctype);
        }
        else
        {
            strlog("Error :", "Only one ctype can be specified");
            return false;
        }
        break;
    case 2:
        if (res->htype == -1)
        {
            res->htype = atoi(optarg);
            printHashMode(res->htype);
        }
        else
        {
            strlog("Error :", "Only one htype can be specified");
            return false;
        }
        break;
    case 'V':
        if (res->mode == 'u')
            res->mode = 'V';
        else
        {
            strlog("Error :", "Only one mode can be specified");
            return false;
        }
        break;

    case 'h':
        if (res->mode == 'u')
            res->mode = 'h';
        else
        {
            strlog("Error :", "Only one mode can be specified");
            return false;
        }

        break;
    default:
        strlog("Error :", "Unknown option");
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
    res->ctype = -1;
    res->htype = -1;
    res->no_echo = false;
    res->fp = NULL;
    res->out = NULL;
    res->key = NULL;
    while (true)
    {
        int c = getopt_long(argc, argv, shortOpts, longOpts, &option_index);
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
        strlog("Error :", "Wrong Mode");
        delete res;
        return NULL;
    }
    else if (res->mode == 'e')
    {
        if (res->ctype == -1)
        {
            printCryptMode(0);
            res->ctype = 0;
        }
        else if (!check_ctype(res->ctype))
        {
            strlog("Error :", "Wrong ctype");
            delete res;
            return NULL;
        }
        if (res->htype == -1)
        {
            printHashMode(0);
            res->htype = 0;
        }
        else if (!check_htype(res->htype))
        {
            strlog("Error :", "Wrong htype");
            delete res;
            return NULL;
        }
        if (res->key == NULL)
        {
            strlog("Key :", "Using random key");
            res->key = getRandomKey();
        }
        if (res->fp == NULL)
        {
            strlog("Error :", "No file specified");
            delete res;
            return NULL;
        }
        if (res->out == NULL)
        {
            strlog("Note :", "Using default output file name");
            res->out = fopen(fout, "wb+");
        }
        getRandomBuffer(res->r_buf);
        printkey(res->key);
    }
    return res->buf;
}

#else

u8_t *get_v_opt(int argc, char *argv[])
{
    strlog("Note :", "CMDLine option is not supported");
    return get_v_mod1();
}

#endif