#include "base64.h"
/*
hex_to_base64:将十六进制串base64编码
hex_in:输入的十六进制串
len:输入串的长度
base64_out:base64编码后的结果
*/
void hex_to_base64(const u8_t *hex_in, int len, u8_t *base64_out) {
  int j = 0, idx = 0;
  u32_t h_in = 0;
  for (int i = 0; i < len; ++i) {
    h_in = h_in | ((u32_t)hex_in[i]) << (8 * (2 - j));
    j = (j + 1) % 3;
    if (j == 0) {
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
}
/*
hex_to_base64:将输入串base64解码为十六进制串
base64_in:输入的base64编码串
len:输入串的长度
hex_out:解码后的十六进制串
*/
void base64_to_hex(const u8_t *base64_in, int len, u8_t *hex_out) {
  int tail = 0, j = 0, idx = 0;
  u32_t h_in = 0;
  for (int i = 0; i < len; ++i)
    if (base64_in[i] == '=')
      tail++;
    else {
      h_in = h_in | (((u32_t)hex_tab[base64_in[i]]) << (6 * (3 - j)));
      j = (j + 1) % 4;
      if (j == 0) {
        for (int j = 0; j < 3; ++j)
          hex_out[idx++] = (h_in >> (8 * (2 - j))) & 0xff;
        h_in = 0;
      }
    }
  if (tail == 1)
    hex_out[idx++] = (h_in >> 16) & 0xff;
  else if (tail == 2) {
    hex_out[idx++] = (h_in >> 16) & 0xff;
    hex_out[idx++] = (h_in >> 8) & 0xff;
  }
}