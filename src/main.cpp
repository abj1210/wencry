#include "key.h"
#include "util.h"
#include "wenctrl.h"
/*
over:关闭文件并释放空间
v1:传入的参数包
*/
static void over(vpak_t v1) {
  delete v1.key;
  if (v1.fp != NULL)
    fclose(v1.fp);
  if (v1.out != NULL)
    fclose(v1.out);
}

int main(int argc, char *argv[]) {
  //初始化
  vpak_t vals;
  if (printterr())
    return -5;
  //获取参数
  if (argc == 1)
    vals = get_v_mod1();
  else if (argc == 5 || argc == 4)
    vals = get_v_mod2(argc, argv);
  else
    return printinv(1);
  //执行任务
  bool flag = exec_val(vals);
  //结束
  over(vals);
  return flag ? 0 : -1;
}