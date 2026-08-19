#ifndef GETOPT_PORT_H
#define GETOPT_PORT_H

#ifdef __cplusplus
extern "C" {
#endif

/*
option:长选项结构
name:长选项名(不含"--")
has_arg:参数要求(no_argument/required_argument/optional_argument)
flag:非NULL时在匹配成功后写入val并返回0
val:选项对应的返回值(或写入*flag的值)
*/
struct option
{
  const char *name;
  int has_arg;
  int *flag;
  int val;
};

#define no_argument 0
#define required_argument 1
#define optional_argument 2

/*
getopt_long 的全局状态:
optarg:当前选项的参数值
optind:下一个待解析参数的索引
opterr:是否打印错误信息
optopt:出错时的选项字符
*/
extern char *optarg;
extern int optind, opterr, optopt;

/*
getopt_long:解析命令行长/短选项(POSIX getopt_long 的轻量实现)
argc/argv:命令行参数个数与参数数组
optstring:短选项串(单字符,后跟':'表示需要参数)
longopts:长选项表
longindex:匹配到的长选项在 longopts 中的下标(可为 NULL)
return:选项字符;解析结束返回 -1,出错返回 '?'
*/
int getopt_long(int argc, char **argv, const char *optstring,
                const struct option *longopts, int *longindex);

#ifdef __cplusplus
}
#endif

#endif
