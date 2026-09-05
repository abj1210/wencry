#include "merkletree.h"
#include <cstring>

/*
模块概述:HMAC 计算
实现标准 RFC 2104 HMAC:
  HMAC = H( (K xor opad) || H( (K xor ipad) || prefix || 数据 ) )
其中 ipad=0x36,opad=0x5c,prefix 为可选域分离前缀(如 Merkle 叶前缀/根前缀)。
对外提供一次性接口 getHmac(基于内存缓冲区),内部由 initHash/feedHash/finalizeHash
三个增量原语完成,结果经 matchResult 做常数时间比较。
*/

/*
constTimeEquals:常数时间比较两个等长字节串(HMAC/摘要比对用,避免 memcmp 提前退出泄露信息)
a,b:待比较数据
len:长度(字节)
return:相等返回 true
*/
static bool constTimeEquals(const u8_t *a, const u8_t *b, u8_t len)
{
    u8_t diff = 0;
    for (u8_t i = 0; i < len; ++i)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

/*
构造函数:初始化全部HMAC状态为空
*/
Hmac::Hmac() : hmac_res(NULL), hashmaster(NULL), blockFast(NULL), key1(NULL), h1(NULL), block_len(0), accum_len(0) {};

/*
析构函数:清理增量HMAC状态
*/
Hmac::~Hmac()
{
    clearIncremental();
    delete[] hmac_res;
}

/*
clearIncremental:释放增量HMAC状态
*/
void Hmac::clearIncremental()
{
    delete[] key1;
    delete[] h1;
    delete hashmaster;
    key1 = NULL;
    h1 = NULL;
    hashmaster = NULL;
    blockFast = NULL;
    accum_len = 0;
}

/*
initHash:初始化增量HMAC,喂入ipad块与prefix(文件头IV区)
hashtype:哈希模式
key:密钥
prefix:需先喂入的前缀数据(IV区)
prefix_len:前缀长度
*/
void Hmac::initHash(u8_t hashtype, u8_t *key, const u8_t *prefix, size_t prefix_len)
{
    hashmaster = hf.getHasher(hf.getType(hashtype));
    blockFast = hashmaster->getBlockFast();
    block_len = hashmaster->getBlockLength();
    length = hashmaster->getHashLength();
    hmac_res = new u8_t[length];
    key1 = new u8_t[block_len];
    h1 = new u8_t[block_len];
    memset(key1, 0, block_len);
    memcpy(key1, key, 16);
    for (int i = 0; i < block_len; ++i)
        h1[i] = key1[i] ^ ipad;
    accum_len = 0;
    hashmaster->resetHash();
    hashmaster->hashBlock(h1);
    feedHash(prefix, prefix_len);
}

/*
feedHash:喂入密文数据,按64字节块缓冲哈希
data:数据
len:数据长度
*/
void Hmac::feedHash(const u8_t *data, size_t len)
{
    // 补齐上一轮残留的部分块(accum_len 可能来自 initHash 的 prefix 或上一块的尾部)
    if (accum_len != 0)
    {
        size_t need = (size_t)(block_len - accum_len);
        size_t take = (len < need) ? len : need;
        memcpy(accum + accum_len, data, take);
        accum_len = (u8_t)(accum_len + take);
        data += take;
        len -= take;
        if (accum_len == block_len)
        {
            blockFast(hashmaster, accum);
            accum_len = 0;
        }
    }
    // 快路径:整块直接从源缓冲哈希,不再逐 64 字节 memcpy 进 accum
    while (len >= (size_t)block_len)
    {
        blockFast(hashmaster, data);
        data += block_len;
        len -= block_len;
    }
    // 尾部不足一块(<64 字节)暂存到 accum,留给下一轮或 finalizeHash
    if (len > 0)
    {
        memcpy(accum, data, len);
        accum_len = (u8_t)len;
    }
}

/*
finalizeHash:完成增量HMAC,结果存于hmac_res
*/
void Hmac::finalizeHash()
{
    u8_t *h2 = new u8_t[block_len + length];
    hashmaster->hashFinal(accum, accum_len);
    for (int i = 0; i < block_len; ++i)
        h2[i] = key1[i] ^ opad;
    hashmaster->getResult(h2 + block_len);
    hashmaster->getStringHash(h2, block_len + length, hmac_res);
    delete[] h2;
    clearIncremental();
}

/*
computeHmac:计算带可选前缀的一次性HMAC(buffer重载)
hashtype:哈希模式
key:密钥序列
buffer:待计算数据
bufsize:数据长度
prefix:可选域分离前缀(如叶子前缀"L"+块号);为NULL时表示无前缀
prefix_len:前缀长度
*/
void Hmac::computeHmac(u8_t hashtype, u8_t *key, const u8_t *buffer, size_t bufsize,const u8_t *prefix, size_t prefix_len){
    initHash(hashtype, key, prefix, prefix_len); // 喂入ipad块与可选前缀
    feedHash(buffer, bufsize);
    finalizeHash();
}

/*
getHmac:获取基于缓冲区的HMAC值
hashtype:哈希模式
key:密钥序列
buf:待计算数据
hmac_out:输出地址
bufsize:数据长度
prefix:可选域分离前缀(为NULL表示无前缀);prefix_len:前缀长度
*/
void Hmac::getHmac(u8_t hashtype, u8_t *key, const u8_t *buf, u8_t *hmac_out, size_t bufsize,u8_t *prefix, size_t prefix_len){
    computeHmac(hashtype, key, buf, bufsize, prefix, prefix_len);
    memcpy(hmac_out, hmac_res, length);
    delete[] hmac_res;
    hmac_res = NULL;
}

/*
matchResult:finalizeHash 后与给定摘要比较
expected:待比较摘要
len:摘要长度
hmac_res:显式传入的摘要缓冲(为NULL时使用内部 hmac_res)
return:一致返回true
*/
bool Hmac::matchResult(const u8_t *expected, u8_t len, u8_t *hmac_res) const
{
    if ((hmac_res == NULL && this->hmac_res == NULL) || len != length)
        return false;
    return constTimeEquals(expected, hmac_res == NULL ? this->hmac_res : hmac_res, len);
}
