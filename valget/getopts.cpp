#include "getval.h"
#include "valhelper.h"
#include <filesystem>
#include <iostream>
#include <string.h>

#ifdef _WIN32
#include "getopt_port.h"
#else
#include <unistd.h>
#include <getopt.h>
#endif

/*################################
  全局变量
################################*/
/*
longOpts:长选项表
--encode/--decode/--verify/--version/--help 对应短选项e/d/v/V/h
--input/--output/--key 需参数,分别对应短选项i/o/k
--cmode/--hmode 需参数,无短选项,返回值1/2
--no_echo 无参数,对应短选项n
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
shortOpts:短选项字符串(带':'的选项需参数)
*/
const char shortOpts[] = "edvVhni:o:k:";
/*
fout:加密模式下的默认输出文件名(输入文件名+".wenc")
*/
char fout[128];
/*################################
  辅助函数
################################*/
/*
printCryptMode:打印AES模式
mode:模式
*/
static void printCryptMode(u8_t mode, WencryInformation wif)
{
    strlog("Crypt mode", std::to_string(mode) + "/" + wif.get_cname(mode));
}
/*
printCryptMode:打印Hash模式
mode:模式
*/
static void printHashMode(u8_t mode, WencryInformation wif)
{
    strlog("Hash mode", std::to_string(mode) + "/" + wif.get_hname(mode));
}
/*
parseOpts:解析选项
c:选项字符
res:参数包指针
return:是否解析成功
*/
bool parseOpts(char c, vpak_t *res, WencryInformation wif)
{
    size_t fsize = 0;
    switch (c)
    {
    case 'e':
        if (res->mode == 'u')
            res->mode = 'e';
        else
        {
            strerr("Error", "Only one mode can be specified");
            return false;
        }
        break;
    case 'd':
        if (res->mode == 'u')
            res->mode = 'd';
        else
        {
            strerr("Error", "Only one mode can be specified");
            return false;
        }
        break;
    case 'v':
        if (res->mode == 'u')
            res->mode = 'v';
        else
        {
            strerr("Error", "Only one mode can be specified");
            return false;
        }
        break;
    case 'i':
        res->fp = fopen(optarg, "rb");
        snprintf(fout, sizeof(fout), "%s.wenc", optarg);
        try
        {
            auto fileSize = std::filesystem::file_size(optarg);
            fsize = fileSize;
            strlog("File size", format_size((size_t)fileSize));
        }
        catch (std::filesystem::filesystem_error &e)
        {
            std::cerr << "Error: " << e.what() << std::endl;
        }
        if (res->fp == NULL)
        {
            strerr("Error", "Could not open file " + std::string(optarg));
            return false;
        }
        res->size = fsize;
        break;
    case 'o':
        res->out = fopen(optarg, "wb+");
        if (res->out == NULL)
        {
            strerr("Error", "Could not open file " + std::string(optarg));
            return false;
        }
        break;
    case 'k':
        res->key = new u8_t[16];
        if (!checkB64Key((u8_t *)optarg, res->key))
        {
            strerr("Error", "Invalid base64 key");
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
        }
        else
        {
            strerr("Error", "Only one ctype can be specified");
            return false;
        }
        break;
    case 2:
        if (res->htype == -1)
        {
            res->htype = atoi(optarg);
        }
        else
        {
            strerr("Error", "Only one htype can be specified");
            return false;
        }
        break;
    case 'V':
        if (res->mode == 'u')
            res->mode = 'V';
        else
        {
            strerr("Error", "Only one mode can be specified");
            return false;
        }
        break;

    case 'h':
        if (res->mode == 'u')
            res->mode = 'h';
        else
        {
            strerr("Error", "Only one mode can be specified");
            return false;
        }

        break;
    default:
        strerr("Error", "Unknown option");
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
    WencryInformation wif;
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
        if (!parseOpts(c, res, wif))
        {
            delete res;
            return NULL;
        }
    }
    if (res->mode == 'u')
    {
        strerr("Error", "Wrong Mode");
        delete res;
        return NULL;
    }
    else if (res->mode == 'e')
    {
        if (res->ctype == -1)
        {
            res->ctype = 0;
        }
        else if (!wif.check_ctype(res->ctype))
        {
            strerr("Error", "Wrong ctype");
            delete res;
            return NULL;
        }
        printCryptMode(res->ctype, wif);
        if (res->htype == -1)
        {
            res->htype = 0;
        }
        else if (!wif.check_htype(res->htype))
        {
            strerr("Error", "Wrong htype");
            delete res;
            return NULL;
        }
        printHashMode(res->htype, wif);
        if (res->key == NULL)
        {
            res->key = getRandomKey();
        }
        if (res->fp == NULL)
        {
            strerr("Error", "No file specified");
            delete res;
            return NULL;
        }
        if (res->out == NULL)
        {
            strlog("Note", "Using default output file name");
            res->out = fopen(fout, "wb+");
        }
        getRandomBuffer(res->r_buf);
        strlog("Key", printkey(res->key));
    }
    else if (res->mode == 'd' || res->mode == 'v')
    {
        if (res->key == NULL)
        {
            strerr("Error", "No key specified");
            delete res;
            return NULL;
        }
        if (res->fp == NULL)
        {
            strerr("Error", "No file specified");
            delete res;
            return NULL;
        }
    }
    return res->buf;
}