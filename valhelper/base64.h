#ifndef B64
#define B64

typedef unsigned char u8_t;
typedef unsigned int u32_t;

/*
hexToBase64:将十六进制字节串进行base64编码
hex_in:输入字节串
len:输入长度
base64_out:编码输出(base64字符,含末尾'\0')
return:成功返回true
*/
bool hexToBase64(const u8_t *hex_in, int len, u8_t *base64_out);
/*
base64ToHex:将base64编码串解码为字节串
base64_in:base64输入串
len:输入长度
hex_out:解码输出字节
return:成功返回true
*/
bool base64ToHex(const u8_t *base64_in, int len, u8_t *hex_out);
/*
isValidBase64:校验base64串的合法性(长度与字符集)
base64_in:base64输入串
len:输入长度
return:合法返回true,否则false
*/
bool isValidBase64(const u8_t* base64_in, u32_t len);

#endif