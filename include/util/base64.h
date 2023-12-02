#ifndef B64
#define B64
typedef unsigned char u8_t;
void hex_to_base64(const u8_t *hex_in, int len, u8_t *base64_out);
void base64_to_hex(const u8_t *base64_in, int len, u8_t *hex_out);
#endif