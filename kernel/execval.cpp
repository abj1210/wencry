#include "execval.h"
#include "cry.h"

/*################################
  定义变量
################################*/
typedef unsigned int u32_t;
/*
vpak:参数包
fp:输入文件
out:输出文件
key:初始密钥
r_buf:随机缓冲数组
mode:模式(加密/解密)
*/
typedef union
{
  struct
  {
    FILE *fp, *out;
    u8_t *key;
    u8_t r_buf[256];
    char mode, ctype;
    bool no_echo;
  };
  u8_t buf[512];
} pakout_t;

/*################################
  辅助函数
################################*/
/*
printinv: 打印非法
return: 返回值
*/
u8_t printinv(const u8_t ret)
{
  std::cout << "Invalid values.\r\n";
  return ret;
}
/*
printtime: 打印时间
totalTime: 总时间
threads_num: 线程数
*/
void printtime(clock_t totalTime, u8_t threads_num)
{
  std::cout << "Time: " << totalTime / ((double)(CLOCKS_PER_SEC * threads_num))
            << "s / " << totalTime / ((double)CLOCKS_PER_SEC) << "s\r\n";
}
/*
printenc: 打印加密结果
*/
void printenc() { std::cout << "Encrypt over! \r\n"; }
/*
printres: 打印解密结果
res: 解密结果
*/
void printres(int res)
{
  if (res <= 0)
    std::cout << "Verify pass!\r\n";
  else if (res == 1)
    std::cout << "File too short.\r\n";
  else if (res == 2)
    std::cout << "Wrong key or File not complete.\r\n";
  else if (res == 3)
    std::cout << "File not complete.\r\n";
  else if (res == 4)
    std::cout << "Wrong magic number.\r\n";
  else
    std::cout << "Unknown res number: " << res << ".\r\n";
}
/*
over:关闭文件并释放空间
v1:传入的参数包
*/
static void over(pakout_t v1)
{
  if (v1.fp != NULL)
    fclose(v1.fp);
  if (v1.out != NULL)
    fclose(v1.out);
}

/*################################
  接口函数
################################*/
/*
exec_val:根据传入的参数包执行相应操作
vals:传入的参数包
return:返回是否成功执行
*/
bool exec_val(unsigned char *v)
{
  if (v == NULL)
    return printinv(0);
  clock_t cl1 = clock();
  pakout_t vals;
  memcpy(vals.buf, v, 512);
  u32_t res = 0;
  runcrypt runner(vals.fp, vals.out, vals.key, vals.ctype, vals.no_echo, THREAD_NUM); // 配置运行器
  if (vals.fp == NULL)
    return printinv(0);
  if (vals.mode == 'e' || vals.mode == 'E')
  {
    runner.enc(vals.r_buf); // 运行加密
    if (!vals.no_echo)
      printenc(); // 打印结果
  }
  else if (vals.mode == 'd' || vals.mode == 'D')
  {
    res = runner.dec(); // 运行解密
    if (!vals.no_echo)
      printres(res); // 打印结果
  }
  else if (vals.mode == 'v')
  {
    res = runner.verify(); // 运行验证
    if (!vals.no_echo)
      printres(res); // 打印结果
  }
  clock_t cl2 = clock();
  if (!vals.no_echo)
    printtime(cl2 - cl1, runner.get_tnum()); // 打印时间
  over(vals);                                // 关闭文件
  return res == 0;
}
