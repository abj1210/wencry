#include "base64.h"
#include "getval.h"
#include <filesystem>

#include <iostream>
#include <iomanip>
#include <stdlib.h>
#include <string.h>
#include <time.h>
void strlog(std::string s1, std::string s2, char fill)
{
  std::cout << std::setw(40) << std::setfill(fill) << std::left << s1 << std::setfill(fill) << std::setw(40) << std::right << s2 << std::endl;
}
void printkey(u8_t *key)
{
  char outk[128];
  hex_to_base64(key, 16, (u8_t *)outk);
  std::string skey = outk;
  strlog("Key is:", skey);
}
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
    int r = scanf("%s", fn);
    fp = fopen(fn, "rb");
    if (fp != NULL)
      break;
    strlog("Error :", "File not found");
  }
  std::filesystem::path filePath(fn);
  std::string fileName = filePath.filename().string();
  try
  {
    auto fileSize = std::filesystem::file_size(fn);
    size = fileSize;
    strlog(fileName + " file size: ", std::to_string(((double)fileSize) / ((double)(1024 * 1024))) + "MB");
  }
  catch (std::filesystem::filesystem_error &e)
  {
    std::cerr << "Error: " << e.what() << std::endl;
  }
  pak->fp = fp;
  pak->size = size;
  return fileName;
}
/*
getRandomKey:获取随机密钥
return:返回的密钥
*/
u8_t *getRandomKey()
{
  srand(time(NULL));
  u8_t *keyout = new u8_t[16];
  for (int i = 0; i < 16; ++i)
    keyout[i] = rand();
  return keyout;
}
/*
getInputFilep:从输入中获取密钥
return:获取的密钥序列
*/
static u8_t *getInputKey()
{
  u8_t kn[128] = "";
  printf("Enter 128 bits (16 bytes) key in base64 mod:\n");
  scanf("%s", kn);
  while (!is_valid_b64(kn, strlen((char *)kn)))
  {
    printf("Sorry, please enter 128 bits (16 bytes) key in base64 mod:\n");
    scanf("%s", kn);
  }
  u8_t *keyout = new u8_t[16];
  base64_to_hex(kn, 24, keyout);
  return keyout;
}
/*
selectCMode:选择加解密模式
return:选择的模式
*/
static u8_t selectCMode()
{
  u32_t c;
  printf("Select a crypt mode(%s).\n", get_ctypelist().c_str());
  scanf("%d", &c);
  if (c > 4 || c < 0)
    c = 0;
  return (u8_t)c;
}
/*
selectHMode:选择哈希模式
return:选择的模式
*/
static u8_t selectHMode()
{
  u32_t h;
  printf("Select a hash mode(%s).\n", get_htypelist().c_str());
  scanf("%d", &h);
  if (h > 2 || h < 0)
    h = 0;
  return (u8_t)h;
}
/*
接口函数
get_v_mod1:根据用户输入获得参数包
return:返回的参数包
*/
u8_t *get_v_mod1()
{
  char flag, fn[] = "out", outn[138], decn[128];
  vpak_t *res = new vpak_t;
  res->no_echo = false;
  version();
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
    strlog("Output File: ", outn);
    res->out = fopen(outn, "wb+");
    printkey(res->key);
    res->ctype = selectCMode();
    res->htype = selectHMode();
    if (res->ctype != 0)
    {
      printf("Please input some random characters.\n");
      int r = scanf("%s", res->r_buf);
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
      scanf("%s", decn);
      res->out = fopen(decn, "wb+");
      strlog("Output File: ", decn);
    }
    else
    {
      sprintf(outn, "%s.wdec", fname.c_str());
      res->out = fopen(outn, "wb+");
      strlog("Output File: ", outn);
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
    help();
  else
    res->fp = NULL;
  return res->buf;
}