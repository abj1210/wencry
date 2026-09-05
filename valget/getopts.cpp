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
/*################################
  辅助函数
################################*/
/*
printCryptMode:打印AES模式
mode:模式
*/
static void printCryptMode(u8_t mode, WencryInformation wif)
{
    logLine("Crypt mode", std::to_string(mode) + "/" + wif.getCryptModeName(mode));
}
/*
printCryptMode:打印Hash模式
mode:模式
*/
static void printHashMode(u8_t mode, WencryInformation wif)
{
    logLine("Hash mode", std::to_string(mode) + "/" + wif.getHashModeName(mode));
}
/*
parseOptions:解析选项
c:选项字符
res:参数包指针
return:是否解析成功
*/
bool parseOptions(char c, vpak_t *res, std::string &fout)
{
    size_t fsize = 0;
    switch (c)
    {
    case 'e':
        if (res->mode == 'u')
            res->mode = 'e';
        else
        {
            logError("Error", "Only one mode can be specified");
            return false;
        }
        break;
    case 'd':
        if (res->mode == 'u')
            res->mode = 'd';
        else
        {
            logError("Error", "Only one mode can be specified");
            return false;
        }
        break;
    case 'v':
        if (res->mode == 'u')
            res->mode = 'v';
        else
        {
            logError("Error", "Only one mode can be specified");
            return false;
        }
        break;
    case 'i':
        res->fp = wencryOpenRead(optarg);
        fout = std::string(optarg) + ".wenc";
        try
        {
            auto fileSize = std::filesystem::file_size(optarg);
            fsize = fileSize;
            logLine("File size", formatSize((size_t)fileSize));
        }
        catch (std::filesystem::filesystem_error &e)
        {
            std::cerr << "Error: " << e.what() << std::endl;
        }
        if (res->fp == NULL)
        {
            logError("Error", "Could not open file " + std::string(optarg));
            return false;
        }
        res->size = fsize;
        break;
    case 'o':
        res->out = wencryOpenWrite(optarg);
        if (res->out == NULL)
        {
            logError("Error", "Could not open file " + std::string(optarg));
            return false;
        }
        break;
    case 'k':
        if (res->key != NULL)
        {
            logError("Error", "Only one key can be specified");
            return false;
        }
        else
        {
            u8_t *tmp = new u8_t[16];
            if (!checkBase64Key((u8_t *)optarg, tmp))
            {
                delete[] tmp;
                logError("Error", "Invalid base64 key");
                return false;
            }
            res->key = tmp;
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
            logError("Error", "Only one ctype can be specified");
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
            logError("Error", "Only one htype can be specified");
            return false;
        }
        break;
    case 'V':
        if (res->mode == 'u')
            res->mode = 'V';
        else
        {
            logError("Error", "Only one mode can be specified");
            return false;
        }
        break;

    case 'h':
        if (res->mode == 'u')
            res->mode = 'h';
        else
        {
            logError("Error", "Only one mode can be specified");
            return false;
        }

        break;
    default:
        logError("Error", "Unknown option");
        return false;
    }
    return true;
}
/*################################
  接口函数
################################*/
/*
failArgsCleanup:解析失败的统一清理入口
关闭已打开的文件句柄、释放密钥与参数包,返回 NULL(与接口约定一致)。
*/
static u8_t *failArgsCleanup(vpak_t *res)
{
    if (res->fp != NULL)
        fclose(res->fp);
    if (res->out != NULL)
        fclose(res->out);
    delete[] res->key;
    delete res;
    return NULL;
}
/*
getCommandLineArgs:解析命令行参数
argc:命令行参数个数
argv:命令行参数数组
return:vpak_t结构体指针x
*/

u8_t *getCommandLineArgs(int argc, char *argv[])
{
    WencryInformation wif;
    std::string fout;
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
    res->r_len = 0;
    while (true)
    {
        int c = getopt_long(argc, argv, shortOpts, longOpts, &option_index);
        if (c == -1)
            break;
        if (!parseOptions(c, res, fout))
        {
            return failArgsCleanup(res);
        }
    }
    if (res->mode == 'u')
    {
        logError("Error", "Wrong Mode");
        return failArgsCleanup(res);
    }
    else if (res->mode == 'e')
    {
        if (res->ctype == -1)
        {
            res->ctype = 1;
        }
        else if (!wif.checkCryptMode(res->ctype))
        {
            logError("Error", "Wrong ctype");
            return failArgsCleanup(res);
        }
        printCryptMode(res->ctype, wif);
        if (res->htype == -1)
        {
            res->htype = 0;
        }
        else if (!wif.checkHashMode(res->htype))
        {
            logError("Error", "Wrong htype");
            return failArgsCleanup(res);
        }
        printHashMode(res->htype, wif);
        if (res->key == NULL)
        {
            res->key = getRandomKey();
        }
        if (res->fp == NULL)
        {
            logError("Error", "No file specified");
            return failArgsCleanup(res);
        }
        if (res->out == NULL)
        {
            logLine("Note", "Using default output file name");
            res->out = wencryOpenWrite(fout.c_str());
        }
        getRandomBuffer(res->r_buf);
        res->r_len = 256;
        logLine("Key", printKey(res->key));
    }
    else if (res->mode == 'd' || res->mode == 'v')
    {
        if (res->key == NULL)
        {
            logError("Error", "No key specified");
            return failArgsCleanup(res);
        }
        if (res->fp == NULL)
        {
            logError("Error", "No file specified");
            return failArgsCleanup(res);
        }
    }
    return res->buf;
}
