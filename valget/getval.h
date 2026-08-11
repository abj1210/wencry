#ifndef GETV
#define GETV
typedef unsigned char u8_t;

/*
get_v_mod1:交互式模式——根据用户控制台输入构造参数包
return:参数包(vpak_t*,以u8_t*返回;失败/无效输入返回NULL)
*/
u8_t *get_v_mod1();
/*
get_v_opt:命令行参数模式——解析argv构造参数包
argc:参数个数
argv:参数数组
return:参数包(vpak_t*,以u8_t*返回;解析失败返回NULL)
*/
u8_t *get_v_opt(int argc, char *argv[]);

#endif