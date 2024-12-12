#include "base64.h"
#include <ctype.h>
#include <string>
/*
hex_to_base64:将十六进制串base64编码
hex_in:输入的十六进制串
len:输入串的长度
base64_out:base64编码后的结果
*/
bool hex_to_base64(const u8_t *hex_in, int len, u8_t *base64_out)
{
  int j = 0, idx = 0;
  u32_t h_in = 0;
  for (int i = 0; i < len; ++i)
  {
    h_in = h_in | ((u32_t)hex_in[i]) << (8 * (2 - j));
    j = (j + 1) % 3;
    if (j == 0)
    {
      for (int j = 0; j < 4; ++j)
        base64_out[idx++] = b64_tab[(h_in >> (6 * (3 - j))) & 0x3f];
      h_in = 0;
    }
  }
  if (j == 1)
    for (int j = 0; j < 4; ++j)
      if (j < 2)
        base64_out[idx++] = b64_tab[(h_in >> (6 * (3 - j))) & 0x3f];
      else
        base64_out[idx++] = '=';
  else if (j == 2)
    for (int j = 0; j < 4; ++j)
      if (j < 3)
        base64_out[idx++] = b64_tab[(h_in >> (6 * (3 - j))) & 0x3f];
      else
        base64_out[idx++] = '=';
  base64_out[idx] = '\0';
  return true;
}
/*
hex_to_base64:将输入串base64解码为十六进制串
base64_in:输入的base64编码串
len:输入串的长度
hex_out:解码后的十六进制串
*/
bool base64_to_hex(const u8_t *base64_in, int len, u8_t *hex_out)
{
  int tail = 0, j = 0, idx = 0;
  u32_t h_in = 0;
  for (int i = 0; i < len; ++i)
    if (base64_in[i] == '=')
      tail++;
    else
    {
      if (base64_in[i] == 255)
        return false;
      h_in = h_in | (((u32_t)hex_tab[base64_in[i]]) << (6 * (3 - j)));
      j = (j + 1) % 4;
      if (j == 0)
      {
        for (int j = 0; j < 3; ++j)
          hex_out[idx++] = (h_in >> (8 * (2 - j))) & 0xff;
        h_in = 0;
      }
    }
  if (tail == 2)
    hex_out[idx++] = (h_in >> 16) & 0xff;
  else if (tail == 1)
  {
    hex_out[idx++] = (h_in >> 16) & 0xff;
    hex_out[idx++] = (h_in >> 8) & 0xff;
  }
  return true;
}

// Base64 字符集

const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

// 判断字符是否是合法的 Base64 字符
bool is_base64(unsigned char c) {
    return std::isalnum(c) || c == '+' || c == '/';
}

bool is_valid_b64(const u8_t* base64_in, int len) {
    int tail = 0;
    if (len % 4 != 0) return false;
    else if ((len / 4) * 3 - 2 != 16) return false;

    // 2. 检查每个字符是否是合法的 Base64 字符或填充字符 '='
    for (int i = 0; i < len; ++i) {
        if (base64_in[i] != '=' && !is_base64(base64_in[i]))
            return false;
        else if (base64_in[i] == '=') {
            tail++;
            if (tail >= 3)
                return false;
        }
        else if (tail != 0)
            return false;
    }
    return true;

}