#include "cry.h"
#include <chrono>
#include <string>
#include <iostream>
#include <math.h>
#include <iomanip>
#include <functional>
using namespace std;
using namespace chrono;

/*################################
  模块概述:HMAC 计算、加密文件头、结果打印
  加密文件(.wenc)布局:
    偏移 0   8字节  魔数 0xA5C3A5C3A5C3A5C3
    偏移 8   1字节  加密模式 ctype(0=ECB..4=OFB)
    偏移 9   1字节  哈希模式 htype(0=sha1,1=md5,2=sha256)
    偏移 10  38字节 HMAC区(加密后写入,长度取决于htype;offset47恒空闲,用于记录线程数num)
    偏移 48  20*num字节 每线程IV
    之后    密文(含PKCS7填充)
   HMAC 结构(标准 RFC 2104):
     HMAC = H( (K xor opad) || H( (K xor ipad) || 数据 ) ),其中 ipad=0x36,opad=0x5c。
   本文件提供两套HMAC计算路径:
     - getres/gethmac/cmphmac:基于 FILE* 分块增量计算(测试/独立验证兼容)。
     - init_hash/feed_hash/final_hash:增量喂入(统一流水线HASH线程融合计算,避免回读)。
################################*/

/*################################
  HMAC函数
################################*/

/*
构造函数
no_echo:是否隐藏输出
*/
hmac::hmac() : res_printer(new SilentDisplay), hmac_res(NULL), hashmaster(NULL), key1(NULL), h1(NULL), block_len(0), accum_len(0) {};

/*
析构函数:清理增量HMAC状态
*/
hmac::~hmac()
{
    clear_incr();
    delete[] hmac_res;
}

/*
clear_incr:释放增量HMAC状态
*/
void hmac::clear_incr()
{
    delete[] key1;
    delete[] h1;
    delete hashmaster;
    key1 = NULL;
    h1 = NULL;
    hashmaster = NULL;
    accum_len = 0;
}

/*
init_hash:初始化增量HMAC,喂入ipad块与prefix(文件头IV区)
hashtype:哈希模式
key:密钥
prefix:需先喂入的前缀数据(IV区)
prefix_len:前缀长度
*/
void hmac::init_hash(u8_t hashtype, u8_t *key, const u8_t *prefix, size_t prefix_len)
{
    hashmaster = hf.getHasher(hf.getType(hashtype));
    block_len = hashmaster->getblen();
    length = hashmaster->gethlen();
    hmac_res = new u8_t[length];
    key1 = new u8_t[block_len];
    h1 = new u8_t[block_len];
    memset(key1, 0, block_len);
    memcpy(key1, key, 16);
    for (int i = 0; i < block_len; ++i)
        h1[i] = key1[i] ^ ipad;
    accum_len = 0;
    hashmaster->reset_hash();
    hashmaster->hash_block(h1);
    feed_hash(prefix, prefix_len);
}

/*
feed_hash:喂入密文数据,按64字节块缓冲哈希
data:数据
len:数据长度
*/
void hmac::feed_hash(const u8_t *data, size_t len)
{
    while (len > 0)
    {
        size_t take = len < (size_t)(block_len - accum_len) ? len : (size_t)(block_len - accum_len);
        memcpy(accum + accum_len, data, take);
        accum_len = (u8_t)(accum_len + take);
        data += take;
        len -= take;
        if (accum_len == block_len)
        {
            hashmaster->hash_block(accum);
            accum_len = 0;
        }
    }
}

/*
final_hash:完成增量HMAC,结果存于hmac_res
*/
void hmac::final_hash()
{
    u8_t *h2 = new u8_t[block_len + length];
    hashmaster->hash_final(accum, accum_len);
    for (int i = 0; i < block_len; ++i)
        h2[i] = key1[i] ^ opad;
    hashmaster->get_result(h2 + block_len);
    hashmaster->getStringHash(h2, block_len + length, hmac_res);
    delete[] h2;
    clear_incr();
}

/*
write_hmac:将hmac_res写入文件指定偏移
fp:文件指针
writeMark:写入偏移
*/
void hmac::write_hmac(FILE *fp, u8_t writeMark)
{
    fseek(fp, writeMark, SEEK_SET);
    fwrite(hmac_res, 1, length, fp);
    delete[] hmac_res;
    hmac_res = NULL;
}

/*
getres:计算HMAC值(基于FILE*当前位置逐块增量计算,不再使用filebuffer64)
hashtype:哈希模式
key:密钥序列
fp:需验证文件指针
fsize:文件大小(仅用于进度,可忽略)
*/
void hmac::getres(u8_t hashtype, u8_t *key, FILE *fp, size_t fsize)
{
    (void)fsize;
    init_hash(hashtype, key, NULL, 0); // 喂入ipad块,无前缀
    u8_t chunk[0x10000];
    size_t n;
    while ((n = fread(chunk, 1, sizeof(chunk), fp)) > 0)
        feed_hash(chunk, (u32_t)n);
    final_hash();
}
/*
gethmac:获取HMAC值
hashtype:哈希模式
key:密钥序列
fp:需验证文件指针
hmac_out:输出地址
fsize:文件大小
*/
void hmac::gethmac(u8_t hashtype, u8_t *key, FILE *fp, u8_t *hmac_out, size_t fsize)
{
    getres(hashtype, key, fp, fsize);
    memcpy(hmac_out, hmac_res, length);
    delete[] hmac_res;
    hmac_res = NULL;
}
/*
cmphmac:校验HMAC值
hashtype:哈希模式
key:密钥序列
fp:需验证文件指针
hmac_out:待校验的HMAC值
fsize:文件大小
return:校验是否成功
*/
bool hmac::cmphmac(u8_t hashtype, u8_t *key, FILE *fp, const u8_t *hmac_out, size_t fsize)
{
    getres(hashtype, key, fp, fsize);
    bool same = true;
    for (int i = 0; i < length; ++i)
        if (hmac_out[i] != hmac_res[i])
        {
            same = false;
            break;
        }
    delete[] hmac_res;
    hmac_res = NULL;
    return same;
}
/*
match_result:final_hash 后与给定摘要比较
expected:待比较摘要
len:摘要长度
return:一致返回true
*/
bool hmac::match_result(const u8_t *expected, u8_t len) const
{
    if (hmac_res == NULL || len != length)
        return false;
    return memcmp(expected, hmac_res, len) == 0;
}
/*################################
  文件头辅助函数
################################*/
/*
getIV:获取初始向量(从输入)
r_buf:随机缓冲数组
iv:初始向量数组
*/
void FileHeader::getIV(const u8_t *r_buf, u8_t *iv)
{
    Hashmaster *hm = hf.getHasher(HT_SHA1);
    size_t len = strnlen((const char *)r_buf, 256);
    hm->getStringHash(r_buf, len, iv);
    for (int i = 1; i < num; ++i)
        hm->getStringHash(iv + (20 * (i - 1)), 20, iv + (20 * i));
    delete hm;
}
/*
getIV:获取初始向量(从文件)
fp:文件指针
iv:初始向量数组
注意:读取后文件指针停在 48+20*num=FILE_TEXT_MARK,解密时 prepare_AES 依赖此定位。
*/
void FileHeader::getIV(FILE *fp, u8_t *iv)
{
    fseek(fp, FILE_IV_MARK, SEEK_SET);
    fread(iv, 1, 20 * num, fp);
}
/*
getFileHeader:构造加密文件头
iv:初始向量数组
*/
void FileHeader::getFileHeader(u8_t *iv)
{
    u8_t padding[PADDING];
    memset(padding, 0, sizeof(padding));
    padding[PADDING - 1] = num;   // 末尾填充字节(offset 47)记录线程数
    u64_t mn = Magic_Num;
    fwrite(&mn, 1, 8, out);
    fwrite(&ctype, 1, 1, out);
    fwrite(&htype, 1, 1, out);
    fwrite(padding, 1, PADDING, out);
    for (int i = 0; i < num; ++i)
        fwrite(iv + (20 * i), 1, 20, out);
}
/*
checkType:检查加密和哈希模式,并读取文件头记录的线程数
线程数记录于offset 47(始终空闲的填充尾,不参与HMAC)。
值为0表示旧格式文件,回退为4线程。
*/
void FileHeader::checkType()
{
    fseek(fp, FILE_MODE_MARK, SEEK_SET);
    fread(&ctype, 1, 1, fp);
    fread(&htype, 1, 1, fp);
    u8_t fn = 0;
    fseek(fp, 47, SEEK_SET);
    // 线程数必须落在 [1, THREAD_MAX] 内,否则回退为4。
    // 不校验上限会让解密路径使用任意大的 num:getIV 读 20*num 字节越过 iv 缓冲、
    // run_multicry 越界写 threads[THREAD_MAX] 数组,导致堆/栈破坏。
    if (fread(&fn, 1, 1, fp) == 1 && fn != 0 && fn <= multicry_master::THREAD_MAX)
        num = fn;
    else
        num = 4;
}
/*
checkMn:检查魔数
*/
bool FileHeader::checkMn()
{
    fseek(fp, FILE_MN_MARK, SEEK_SET);
    u64_t mn = 0;
    int sum = fread(&mn, 1, 8, fp);
    if (sum != 8)
        return false;
    return (mn == Magic_Num);
}
/*
getHmac:获得HMAC
len:hmac长度(应与htype对应:16/20/32)
return:HMAC地址(不足len字节返回NULL)
*/
u8_t *FileHeader::getHmac(u8_t len)
{
    fseek(fp, FILE_HMAC_MARK, SEEK_SET);
    int sum = fread(hash, 1, len, fp);
    if (sum != len)
        return NULL;
    return hash;
}