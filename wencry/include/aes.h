#ifndef AES
#define AES

#define sub_bytes(x) s_box[((x) >> 4)][((x)&0x0f)]
#define r_sub_bytes(x) rs_box[((x) >> 4)][((x)&0x0f)]
#define lrot(x, i) (((x) << (i)) | ((x) >> (32 - i)))
#define rrot(x, i) (((x) >> (i)) | ((x) << (32 - i)))
#define GMul(u, v) \
  ((u) && (v) ? Alogtable[mod255(Logtable[(u)] + Logtable[(v)])] : 0)
#define mod255(x) ((x & 255) + (x >> 8))

extern const unsigned char RC[11];
extern const unsigned char MA[4][4], RMA[4][4];
extern const unsigned char s_box[16][16], rs_box[16][16];
extern const unsigned char Logtable[256], Alogtable[256];

struct state {
  unsigned char s[4][4];
};
extern struct state keyg[11];

struct state genkey(struct state last_key, int round);
struct state* addroundkey(struct state* w, struct state* key);
struct state* subbytes(struct state* w);
struct state* rowshift(struct state* w);
struct state* columnmix(struct state* w);
void initgen(unsigned char* init_key);

struct state* resubbytes(struct state* w);
struct state* rerowshift(struct state* w);
struct state* recolumnmix(struct state* w);

struct state* commonround(struct state* data, int round);
struct state* lastround(struct state* data);

struct state* commondec(struct state* data, int round);
struct state* firstdec(struct state* data);

unsigned char* runaes_128bit(unsigned char* s, unsigned char* out);
unsigned char* decaes_128bit(unsigned char* s, unsigned char* out);

#endif