#include "valhelper.h"
#include "getval.h"
#include <iostream>
#include <iomanip>
#include <string>
#include <filesystem>
#include <string.h>
#include <time.h>

/*
getInputFileName:从输入中获取文件指针
return:获取的文件名
*/
static std::string getInputFileName(vpak_t *pak)
{
  char fn[128];
  size_t size = 0;
  FILE *fp;
  while (1)
  {
    scanf("%127s", fn);
    fp = wencryOpenRead(fn);
    if (fp != NULL)
      break;
    logError("Error", "File not found");
  }
  std::string path(fn);
  size_t pos = path.find_last_of("/\\");
  std::string filename = (pos == std::string::npos) ? path : path.substr(pos + 1);
  try
  {
    size = (size_t)std::filesystem::file_size(path);
  }
  catch (std::filesystem::filesystem_error &e)
  {
    size = 0;
  }
  logLine("File size", formatSize((size_t)size));
  pak->fp = fp;
  pak->size = size;
  return filename;
}
/*
getInputFileName:从输入中获取密钥
return:获取的密钥序列
*/
static u8_t *getInputKey()
{
  u8_t kn[128] = "";
  u8_t *keyout = new u8_t[16];
  printf("Enter 128 bits (16 bytes) key in base64 mode:\n");
  scanf("%127s", kn);
  while (!checkBase64Key(kn, keyout))
  {
    printf("Sorry, please enter 128 bits (16 bytes) key in base64 mode:\n");
    scanf("%127s", kn);
  }
  return keyout;
}
/*
selectCryptMode:选择加解密模式
return:选择的模式
*/
static u8_t selectCryptMode(WencryInformation wif)
{
  int c = -1;
  printf("Select a crypt mode(%s).\n", wif.getCryptModeList().c_str());
  scanf("%d", &c);
  while (!wif.checkCryptMode(c))
  {
    scanf("%*[^\n]");
    printf("Sorry, please enter a valid mode(%s).\n", wif.getCryptModeList().c_str());
    scanf("%d", &c);
  }
  logLine("Crypt mode", wif.getCryptModeName(c));
  return (u8_t)c;
}
/*
selectHashMode:选择哈希模式
return:选择的模式
*/
static u8_t selectHashMode(WencryInformation wif)
{
  int h = -1;
  printf("Select a hash mode(%s).\n", wif.getHashModeList().c_str());
  scanf("%d", &h);
  while (!wif.checkHashMode(h))
  {
    scanf("%*[^\n]");
    printf("Sorry, please enter a valid mode(%s).\n", wif.getHashModeList().c_str());
    scanf("%d", &h);
  }
  logLine("Hash mode", wif.getHashModeName(h));
  return (u8_t)h;
}
/*
接口函数
getInteractiveArgs:根据用户输入获得参数包
return:返回的参数包
*/
u8_t *getInteractiveArgs()
{
  char flag, outn[138], decn[128];
  WencryInformation wif;
  vpak_t *res = new vpak_t;
  res->no_echo = false;
  res->r_len = 0;
  memset(res->r_buf, 0, sizeof(res->r_buf));
  logLine("Kernel version", wif.getVersion());
  logLine("Build time", wif.getBuildTime());
  printf("Need encrypt, verify , decrypt or help?(e/v/d/h) ");
  scanf("%c", &res->mode);
  printf("File name:\n");
  std::string fname = getInputFileName(res);
  if (res->mode == 'e' || res->mode == 'E')
  {
    printf("Need generate a new key?(y/n) ");
    scanf("%*[\n]%c", &flag);
    if (flag == 'y' || flag == 'Y')
      res->key = getRandomKey();
    else
      res->key = getInputKey();
    sprintf(outn, "%s.wenc", fname.c_str());
    logLine("Output file", outn);
    res->out = wencryOpenWrite(outn);
    logLine("Key", printKey(res->key));
    res->ctype = selectCryptMode(wif);
    res->htype = selectHashMode(wif);
    if (res->ctype != 0)
    {
      printf("Please input some random characters.\n");
      scanf("%255s", res->r_buf);
      res->r_len = strlen((char *)res->r_buf);
    }
  }
  else if (res->mode == 'd' || res->mode == 'D')
  {
    printf("Need a new name for decrypted file?(y/n) ");
    scanf("%*[\n]%c", &flag);
    if (flag == 'y' || flag == 'Y')
    {
      printf("Enter new name:\n");
      scanf("%*[\n]");
      scanf("%127s", decn);
      res->out = wencryOpenWrite(decn);
      logLine("Output file", decn);
    }
    else
    {
      sprintf(outn, "%s.wdec", fname.c_str());
      res->out = wencryOpenWrite(outn);
      logLine("Output file", outn);
    }
    res->key = getInputKey();
    res->ctype = -1;
    res->htype = -1;
  }
  else if (res->mode == 'v')
  {
    res->key = getInputKey();
    res->out = NULL;
    res->ctype = -1;
    res->htype = -1;
  }
  else if (res->mode == 'h')
    std::cout << wif.getHelp();
  else
    res->fp = NULL;
  return res->buf;
}
