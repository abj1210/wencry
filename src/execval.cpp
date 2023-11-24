#include "cry.h"
#include "util.h"
#include "wenctrl.h"

#include <time.h>

/*
encrypt: 根据传入的参数包设置加密参数并运行加密程序
v1: 传入的参数包
reutrn: 操作时间
*/
clock_t encrypt(struct vpak v1) {
  clock_t cl1, cl2;
  cl1 = clock();
  enc(v1.fp, v1.out, v1.key);
  cl2 = clock();
  printf("Encrypt over! \n");

  return cl2 - cl1;
}

/*
decrypt: 根据传入的参数包设置加密参数并运行解密程序
v1: 传入的参数包
reutrn: 操作时间
*/
clock_t decrypt(struct vpak v1) {
  clock_t cl1, cl2;
  cl1 = clock();
  int res = dec(v1.fp, v1.out, v1.key);
  cl2 = clock();

  if (res == 0)
    printf("Decrypt over!\n");
  else if (res == 1)
    printf("File too short.\n");
  else if (res == 2)
    printf("Wrong key.\n");
  else if (res == 3)
    printf("File not complete.\n");
  return cl2 - cl1;
}
/*
verify: 根据传入的参数包验证密钥和文件
v1: 传入的参数包
reutrn: 操作时间
*/
clock_t get_verify(struct vpak v1) {
  clock_t cl1, cl2;
  cl1 = clock();
  int res = verify(v1.fp, v1.key);
  cl2 = clock();

  if (res >= 0)
    printf("File verified!\n");
  else if (res == -1)
    printf("File too short.\n");
  else if (res == -2)
    printf("Wrong key.\n");
  else if (res == -3)
    printf("File not complete.\n");
  return cl2 - cl1;
}
/*
接口函数
exec_val:根据传入的参数包执行相应操作
vals:传入的参数包
return:执行时间
*/
clock_t exec_val(struct vpak vals) {
  if (vals.fp == NULL) {
    printf("Invalid values.\n");
    return -1;
  }
  clock_t totalTime;
  if (vals.mode == 'e' || vals.mode == 'E')
    totalTime = encrypt(vals);
  else if (vals.mode == 'd' || vals.mode == 'D')
    totalTime = decrypt(vals);
  else if (vals.mode == 'v')
    totalTime = get_verify(vals);
  return totalTime;
}