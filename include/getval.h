#ifndef GETV
#define GETV

struct vpak{
  FILE * fp, *out;
  unsigned char * key;
  char mode;
};

struct vpak get_v_mod1();
struct vpak get_v_mod2(int argc, char * argv[]);
unsigned char * hex_to_base64(unsigned char * hex_in);
unsigned char * base64_to_hex(unsigned char * base64_in);


#endif