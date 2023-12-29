#ifndef B64
#define B64

#include "tab.h"
bool hex_to_base64(const u8_t *hex_in, int len, u8_t *base64_out);
bool base64_to_hex(const u8_t *base64_in, int len, u8_t *hex_out);

#endif