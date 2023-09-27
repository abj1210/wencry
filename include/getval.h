#ifndef GETV
#define GETV

struct vpak get_v_mod1();
struct vpak get_v_mod2(int argc, char *argv[]);

unsigned char turn_base64(unsigned char in);
unsigned char turn_hex(unsigned char in);
void hex_to_base64(unsigned char *hex_in, int len, unsigned char *base64_out);
void base64_to_hex(unsigned char *base64_in, int len, unsigned char *hex_out);

#endif