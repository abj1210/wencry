#ifndef TST
#define TST

#include <stdio.h>

typedef unsigned char u8_t;

/*
exec:按argv执行一次加解密任务(复用命令行参数解析与runcrypt内核)
argc:参数个数
argv:参数数组(首元素为程序名)
return:执行成功返回true,失败返回false
*/
bool exec(int argc, char *argv[]);
/*
cmp_file:逐块比较两个文件内容是否一致
x:文件1
y:文件2
return:一致返回1,不一致返回0
*/
int cmp_file(FILE *x, FILE *y);
/*
makeFullTest:对字符串str进行"加密->解密->比对"完整往返测试
str:测试内容
type:type低4位=加密模式,高4位=哈希模式
return:往返一致返回1,否则0
*/
int makeFullTest(const char *str, u8_t type = 0);
/*
makeBigTest:对约32MB大文件进行往返测试
offset:文件中置0的偏移位置
type:加密模式
return:往返一致返回1,否则0
*/
int makeBigTest(int offset, u8_t type = 0);
/*
makeSpeedTest:测量指定加密模式的加密吞吐量
type:加密模式
return:成功返回吞吐量(MB/s),失败返回0
*/
double makeSpeedTest(u8_t type = 0);

#endif