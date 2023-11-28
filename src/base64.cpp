#include "wenctrl.h"
/*
turn_base64:将一个十六进制位转化为base64编码
in:输入的十六进制位
return:转化的base64编码
*/
unsigned char turn_base64(unsigned char in) {
  unsigned char res;
  if (in < 26)
    res = 'A' + in;
  else if (in < 52)
    res = 'a' + in - 26;
  else if (in < 62)
    res = '0' + in - 52;
  else if (in == 62)
    res = '+';
  else
    res = '/';
  return res;
}
/*
turn_base64:将base64编码转化为一个十六进制位
in:输入的base64编码
return:转化的十六进制位
*/
unsigned char turn_hex(unsigned char in) {
  unsigned char res;
  if (in >= 'A' && in <= 'Z')
    res = in - 'A';
  else if (in >= 'a' && in <= 'z')
    res = in - 'a' + 26;
  else if (in >= '0' && in <= '9')
    res = in - '0' + 52;
  else if (in == '+')
    res = 62;
  else
    res = 63;
  return res;
}
/*
hex_to_base64:将十六进制串base64编码
hex_in:输入的十六进制串
len:输入串的长度
base64_out:base64编码后的结果
*/
void hex_to_base64(unsigned char *hex_in, int len, unsigned char *base64_out) {
  int j = 0;
  int idx = 0;
  unsigned h_in = 0;
  for (int i = 0; i < len; i++) {
    h_in = h_in | ((unsigned int)hex_in[i]) << (8 * (2 - j));
    j = (j + 1) % 3;
    if (j == 0) {
      for (int j = 0; j < 4; j++)
        base64_out[idx++] = turn_base64((h_in >> (6 * (3 - j))) & 0x3f);
      h_in = 0;
    }
  }
  if (j == 1) {
    for (int j = 0; j < 4; j++) {
      if (j < 2)
        base64_out[idx++] = turn_base64((h_in >> (6 * (3 - j))) & 0x3f);
      else
        base64_out[idx++] = '=';
    }
  } else if (j == 2) {
    for (int j = 0; j < 4; j++) {
      if (j < 3)
        base64_out[idx++] = turn_base64((h_in >> (6 * (3 - j))) & 0x3f);
      else
        base64_out[idx++] = '=';
    }
  }
  base64_out[idx] = '\0';
}
/*
hex_to_base64:将输入串base64解码为十六进制串
base64_in:输入的base64编码串
len:输入串的长度
hex_out:解码后的十六进制串
*/
void base64_to_hex(unsigned char *base64_in, int len, unsigned char *hex_out) {
  int tail = 0;
  int j = 0;
  int idx = 0;
  unsigned h_in = 0;
  for (int i = 0; i < len; i++) {
    if (base64_in[i] == '=')
      tail++;
    else {
      h_in = h_in | (((unsigned int)turn_hex(base64_in[i])) << (6 * (3 - j)));
      j = (j + 1) % 4;
      if (j == 0) {
        for (int j = 0; j < 3; j++)
          hex_out[idx++] = (h_in >> (8 * (2 - j))) & 0xff;
        h_in = 0;
      }
    }
  }
  if (tail == 1) {
    hex_out[idx++] = (h_in >> 16) & 0xff;
  } else if (tail == 2) {
    hex_out[idx++] = (h_in >> 16) & 0xff;
    hex_out[idx++] = (h_in >> 8) & 0xff;
  }
}