#ifndef AES
#define AES
// 将x循环左移i位

#define lrot(x, i) (((x) << (i)) | ((x) >> (32 - i)))
// 将x循环右移i位

#define rrot(x, i) (((x) >> (i)) | ((x) << (32 - i)))
// 对byteint每字节赋值

#define setbytes(t, b0, b1, b2, b3) \
  t = ((u32_t)b0) | ((u32_t)b1 << 8) | ((u32_t)b2 << 16) | ((u32_t)b3 << 24)

// 在GF(255)上执行乘法

#define Gmul(u, v) ((v) ? Alogtable[(u) + Logtable[(v)]] : 0)

// 在GF(255)上执行加法

#define GMumLine(n0, n1, n2, n3)                                        \
  (Gmul(n0, (u8_t)(g0)) ^ Gmul(n1, (u8_t)(g1)) ^ Gmul(n2, (u8_t)(g2)) ^ \
   Gmul(n3, (u8_t)(g3)))

typedef unsigned char u8_t;
typedef unsigned short u16_t;
typedef unsigned int u32_t;
typedef unsigned long long u64_t;

/*
state:用于aes操作的基本单元
s:16B数据
*/
typedef union
{
  struct
  {
    u64_t datal, datah;
  };
  u32_t g[4];
  u8_t s[4][4];
} state_t;
class aeshandle
{
protected:
  state_t w;
  /*
  keyhandle:密钥的生成
  key:轮密钥
  init_key:初始密钥序列
  */
  class keyhandle
  {
    state_t key[11];
    u8_t init_key[20];
    void genkey(int round);
    void genall();

  public:
    keyhandle(const u8_t *initkey);
    /*
    get_key:获取相应轮次的密钥
    round:指定的轮次
    return:返回的密钥
    */
    const state_t &get_key(int round) { return key[round]; };
  } key;

public:
  /*
  构造函数:加载密钥
  key:待加载的密钥
  */
  aeshandle(const u8_t *initkey) : key(initkey){};
  virtual void runaes_128bit(u8_t *w) = 0;
};
class encryaes : public aeshandle
{
public:
  encryaes(const u8_t *initkey) : aeshandle(initkey){};
  void runaes_128bit(u8_t *w) override;
};
class decryaes : public aeshandle
{
public:
  decryaes(const u8_t *initkey) : aeshandle(initkey){};
  void runaes_128bit(u8_t *w) override;
};

#endif