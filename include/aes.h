#ifndef AES
#define AES

void initgen(unsigned char *init_key);
void runaes_128bit(unsigned char *s);
void decaes_128bit(unsigned char *s);

#endif