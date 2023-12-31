#include "config.h"
#include "execval.h"
#include "getval.h"
#include <iostream>
/*
version:获取版本信息
*/
void version() {
  std::cout << "Wencry version: " << PROJECT_VERSION
            << ". Build time: " << V_BUILD_TIME << "\r\n";
}
int main(int argc, char *argv[]) {
  //初始化
  unsigned char *vals = NULL;
  //获取参数
  if (argc == 1)
    vals = get_v_mod1();
  else if (argc == 2 && argv[1][1] == 'V') {
    version();
    return 0;
  } else if (argc >= 4)
    vals = get_v_mod2(argc, argv);
  else
    return 1;
  //执行任务
  bool flag = exec_val(vals);
  return flag ? 0 : -1;
}