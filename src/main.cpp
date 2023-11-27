#include "util.h"
#include "wenctrl.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/*
over:关闭文件并释放空间
v1:传入的参数包
*/
void over(struct vpak v1) {
  delete[] v1.key;
  if (v1.fp != NULL)
    fclose(v1.fp);
  if (v1.out != NULL)
    fclose(v1.out);
}

int main(int argc, char *argv[]) {
  //初始化
  srand(time(NULL));
  struct vpak vals;
#ifdef MULTI_ENABLE
  if (THREADS_NUM >= MAX_THREADS) {
    printf("Invalid threads number!\n");
    return -4;
  }
#endif

  //获取参数
  if (argc == 1)
    vals = get_v_mod1();
  else if (argc == 5 || argc == 4)
    vals = get_v_mod2(argc, argv);
  else {
    printf("Invalid values.\n");
    return 1;
  }

  //执行任务
  clock_t totalTime = exec_val(vals);
  if (totalTime == -1)
    return -1;

#ifndef MULTI_ENABLE
  printf("Time: %lfs\n", totalTime / ((double)CLOCKS_PER_SEC));
#else
  printf("Time: %lfs\n", totalTime / ((double)(CLOCKS_PER_SEC * THREADS_NUM)));
#endif
  //结束
  over(vals);
  return 0;
}