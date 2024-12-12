
#include "cry.h"
#include "getval.h"
#include <iostream>

int main(int argc, char *argv[])
{
  // 初始化

  unsigned char *vals = NULL;
  // 获取参数

  if (argc == 1)
    vals = get_v_mod1();
  else
  {
    vals = get_v_opt(argc, argv);
    if (vals == NULL)
      return 1;
    if (((vpak_t *)vals)->mode == 'V')
    {
      version();
      return 0;
    }
    else if (((vpak_t *)vals)->mode == 'h')
    {
      help();
      return 0;
    }
  }
  Settings settings(((vpak_t *)vals)->ctype, ((vpak_t *)vals)->htype, ((vpak_t *)vals)->no_echo);
  bool flag;
  // 执行任务
  runcrypt runner(((vpak_t *)vals)->fp, ((vpak_t *)vals)->out, ((vpak_t *)vals)->key, settings);
  if (((vpak_t *)vals)->mode == 'e' || ((vpak_t *)vals)->mode == 'E')
    flag = runner.execute_encrypt(((vpak_t *)vals)->size, ((vpak_t *)vals)->r_buf);
  else if (((vpak_t *)vals)->mode == 'd' || ((vpak_t *)vals)->mode == 'D')
    flag = runner.execute_decrypt(((vpak_t *)vals)->size);
  else if (((vpak_t *)vals)->mode == 'v')
    flag = runner.execute_verify(((vpak_t *)vals)->size);
  else
    return -2;
  return flag ? 0 : -1;
}