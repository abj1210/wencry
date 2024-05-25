
#include "cry.h"
#include "getval.h"
#include <iostream>

int main(int argc, char *argv[]) {
  //初始化
  unsigned char *vals = NULL;
  //获取参数
  if (argc == 1)
    vals = get_v_mod1();
  else {
    vals = get_v_opt(argc, argv);
    if(vals == NULL)
      return 1;
    if(((vpak_t *)vals)->mode == 'V'){
      version();
      return 0;
    }
    else if(((vpak_t *)vals)->mode == 'h'){
      help();
      return 0;
    }
  }
  //执行任务
  runcrypt runner(vals);
  bool flag = runner.exec_val();
  return flag ? 0 : -1;
}