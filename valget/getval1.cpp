#include "valhelper.h"
#include "getval.h"
#include <iostream>
#include <iomanip>
#include <string>
#include <filesystem>
#include <string.h>
#include <time.h>

/*
getInputFilep:从输入中获取文件指针
return:获取的文件名
*/
static std::string getInputFilep(vpak_t *pak)
{
  char fn[128];
  size_t size = 0;
  FILE *fp;
  while (1)
  {
    scanf("%127s", fn);
    fp = fopen(fn, "rb");
    if (fp != NULL)
      break;
    strerr("Error", "File not found");
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
  strlog("File size", format_size((size_t)size));
  pak->fp = fp;
  pak->size = size;
  return filename;
}
/*
getInputFilep:从输入中获取密钥
return:获取的密钥序列
*/
static u8_t *getInputKey()
{
  u8_t kn[128] = "";
  u8_t *keyout = new u8_t[16];
  printf("Enter 128 bits (16 bytes) key in base64 mode:\n");
  scanf("%127s", kn);
  while (!checkB64Key(kn, keyout))
  {
    printf("Sorry, please enter 128 bits (16 bytes) key in base64 mode:\n");
    scanf("%127s", kn);
  }
  return keyout;
}
/*
selectCMode:选择加解密模式
return:选择的模式
*/
static u8_t selectCMode(WencryInformation wif)
{
  int c = -1;
  printf("Select a crypt mode(%s).\n", wif.get_ctypelist().c_str());
  scanf("%d", &c);
  while (!wif.check_ctype(c))
  {
    scanf("%*[^\n]");
    printf("Sorry, please enter a valid mode(%s).\n", wif.get_ctypelist().c_str());
    scanf("%d", &c);
  }
  strlog("Crypt mode", wif.get_cname(c));
  return (u8_t)c;
}
/*
selectHMode:选择哈希模式
return:选择的模式
*/
static u8_t selectHMode(WencryInformation wif)
{
  int h = -1;
  printf("Select a hash mode(%s).\n", wif.get_htypelist().c_str());
  scanf("%d", &h);
  while (!wif.check_htype(h))
  {
    scanf("%*[^\n]");
    printf("Sorry, please enter a valid mode(%s).\n", wif.get_htypelist().c_str());
    scanf("%d", &h);
  }
  strlog("Hash mode", wif.get_hname(h));
  return (u8_t)h;
}
/*
接口函数
get_v_mod1:根据用户输入获得参数包
return:返回的参数包
*/
u8_t *get_v_mod1()
{
  char flag, outn[138], decn[128];
  WencryInformation wif;
  vpak_t *res = new vpak_t;
  res->no_echo = false;
  res->r_len = 0;
  memset(res->r_buf, 0, sizeof(res->r_buf));
  strlog("Kernel version", wif.get_version());
  strlog("Build time", wif.get_buildtime());
  printf("Need encrypt, verify , decrypt or help?(e/v/d/h) ");
  scanf("%c", &res->mode);
  printf("File name:\n");
  std::string fname = getInputFilep(res);
  if (res->mode == 'e' || res->mode == 'E')
  {
    printf("Need generate a new key?(y/n) ");
    scanf("%*[\n]%c", &flag);
    if (flag == 'y' || flag == 'Y')
      res->key = getRandomKey();
    else
      res->key = getInputKey();
    sprintf(outn, "%s.wenc", fname.c_str());
    strlog("Output file", outn);
    res->out = fopen(outn, "wb+");
    strlog("Key", printkey(res->key));
    res->ctype = selectCMode(wif);
    res->htype = selectHMode(wif);
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
      res->out = fopen(decn, "wb+");
      strlog("Output file", decn);
    }
    else
    {
      sprintf(outn, "%s.wdec", fname.c_str());
      res->out = fopen(outn, "wb+");
      strlog("Output file", outn);
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
    std::cout << wif.get_help();
  else
    res->fp = NULL;
  return res->buf;
}