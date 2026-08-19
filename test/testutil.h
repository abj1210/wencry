#ifndef TUL
#define TUL

#include <stdio.h>
/* genfile:生成临时文件并写入字符串 str,返回只读文件句柄(见 testutil.cpp) */
FILE *genfile(const char *str);
/* gethex:将十六进制字符串解析为字节数组(见 testutil.cpp) */
void gethex(const char *str, unsigned char *out);
/* cmpstr:逐字节比较两段内存前 n 字节是否一致(见 testutil.cpp) */
bool cmpstr(const unsigned char *s1, const unsigned char *s2, int n);
/* make_tmp_name:生成跨进程唯一的临时文件名(见 testutil.cpp) */
void make_tmp_name(char *out, size_t cap, const char *tag);
/* write_pattern_file:写入确定性内容的测试文件(见 testutil.cpp) */
void write_pattern_file(const char *fname, size_t size);

#endif