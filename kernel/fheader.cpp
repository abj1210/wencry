#include "cry.h"

/*################################
  模块概述:加密文件头、结果打印
  加密文件(.wenc)布局:
    偏移 0   8字节  魔数 0xA5C3A5C3A5C3A5C3
    偏移 8   1字节  加密模式 ctype(0=ECB..4=OFB)
    偏移 9   1字节  哈希模式 htype(0=sha1,1=md5,2=sha256)
    偏移 10  38字节 HMAC区(加密后写入,长度取决于htype;offset47恒空闲,用于记录线程数num)
    偏移 48  20*num字节 每线程IV
    之后    密文(含PKCS7填充)
################################*/

/*################################
  文件头辅助函数
################################*/
/*
getIv:获取初始向量(从输入)
r_buf:随机缓冲数组
iv:初始向量数组
*/
void FileHeader::getIv(const u8_t *r_buf, size_t r_len, u8_t *iv)
{
    HashMaster *hm = hf.getHasher(HT_SHA1);
    // r_len==0 表示调用方未显式给出长度(兼容旧接口/GUI),按 C 字符串长度处理;
    // 命令行随机缓冲路径传入 256,避免随机字节中的 0x00 截断 IV 种子。
    if (r_len == 0)
        r_len = strnlen((const char *)r_buf, 256);
    hm->getStringHash(r_buf, (u32_t)r_len, iv);
    for (int i = 1; i < num; ++i)
        hm->getStringHash(iv + (20 * (i - 1)), 20, iv + (20 * i));
    delete hm;
}
/*
getIv:获取初始向量(从文件)
fp:文件指针
iv:初始向量数组
注意:读取后文件指针停在 48+20*num=FILE_TEXT_MARK,解密时 prepareAes 依赖此定位。
*/
void FileHeader::getIv(FILE *fp, u8_t *iv)
{
    fseek(fp, FILE_IV_MARK, SEEK_SET);
    fread(iv, 1, 20 * num, fp);
}
/*
writeFileHeader:构造加密文件头
iv:初始向量数组
*/
void FileHeader::writeFileHeader(u8_t *iv)
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
checkHeader:校验 .wenc 文件头(魔数/加密模式/哈希模式)
return:0=合法,1=文件过短,3=加密/哈希模式非法,4=魔数错误
返回值与 RunCrypt::checkHeader 的 res 码一致,可直接透传。
线程数越界(>THREAD_MAX)不在此校验,交由 checkType 回退为4线程。
函数不改变 fp 的读写位置。
*/
int FileHeader::checkHeader()
{
    if (fp == NULL)
        return 4;
    long pos = ftell(fp);
    if (fseek(fp, 0, SEEK_SET) != 0)
    {
      fseek(fp, pos, SEEK_SET);
      return 4;
    }
    u8_t hdr[48];
    size_t rd = fread(hdr, 1, sizeof(hdr), fp);
    fseek(fp, pos, SEEK_SET);
    if (rd < sizeof(hdr))
        return 1;
    // Magic_Num = 0xA5C3A5C3A5C3A5C3,小端写入磁盘的字节序为 C3 A5 C3 A5 C3 A5 C3 A5
    u64_t mn = 0;
    memcpy(&mn, hdr, 8);
    if (mn != Magic_Num)
        return 4;
    if (hdr[FILE_MODE_MARK] >= kCryptModeCount || hdr[FILE_MODE_MARK + 1] >= kHashModeCount)
        return 3;
    return 0;
}

/*
writeHmac:把已计算的HMAC写入输出文件指定偏移(文件头HMAC区)
Hmac:HMAC摘要地址
hsize:摘要长度(字节)
writeMark:写入偏移(通常为 FILE_HMAC_MARK)
注意:写入目标为 out 文件指针,且只移动 out 的读写位置。
*/
void FileHeader::writeHmac(u8_t *Hmac, size_t hsize, u8_t writeMark){
    fseek(out, writeMark, SEEK_SET);
    fwrite(Hmac, 1, hsize, out);
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
    // 不校验上限会让解密路径使用任意大的 num:getIv 读 20*num 字节越过 iv 缓冲、
    // runMulticry 越界写 threads[THREAD_MAX] 数组,导致堆/栈破坏。
    if (fread(&fn, 1, 1, fp) == 1 && fn != 0 && fn <= MulticryMaster::THREAD_MAX)
        num = fn;
    else
        num = 4;
}
/*
getHmac:获得HMAC
len:Hmac长度(应与htype对应:16/20/32)
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
