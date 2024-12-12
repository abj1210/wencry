#include "cry.h"
#include "hashbuffer.h"
#include <chrono>
#include <string>
#include <iostream>
#include <math.h>
#include <iomanip>
#include <functional>
using namespace std;
using namespace chrono;
/*################################
  HMAC函数
################################*/

/*
构造函数
no_echo:是否隐藏输出
*/
hmac::hmac() : res_printer(new NullResPrint) {};

const u8_t hmac::get_length() { return length; };

/*
getres:计算HMAC值
hashtype:哈希模式
key:密钥序列
fp:需验证文件指针
fsize:文件大小
*/
void hmac::getres(u8_t hashtype, u8_t *key, FILE *fp, size_t fsize)
{
    // 准备数据
    Hashmaster *hashmaster = hf.getHasher(hf.getType(hashtype));
    const u8_t block = hashmaster->getblen();
    length = hashmaster->gethlen();
    hmac_res = new u8_t[length];
    u8_t *key1 = new u8_t[block], *h1 = new u8_t[block], *h2 = new u8_t[block + length];
    memset(key1, 0, sizeof(u8_t) * block);
    memcpy(key1, key, 16);
    // 计算hmac
    for (int i = 0; i < block; ++i)
        h1[i] = key1[i] ^ ipad;
    auto boundfunc = bind(&AbsResultPrint::printpercentage, res_printer, std::placeholders::_1, std::placeholders::_2, fsize == 0 ? 1 : fsize);
    buf = new filebuffer64(fp, boundfunc, h1);
    hashmaster->getFileHash(buf, &h2[block], boundfunc);
    for (int i = 0; i < block; ++i)
        h2[i] = key1[i] ^ opad;
    hashmaster->getStringHash(h2, block + length, hmac_res);
    // 清理数据
    delete[] key1, h1, h2;
    delete buf, hashmaster;
    buf = NULL;
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
    for (int i = 0; i < length; ++i)
        if (hmac_out[i] != hmac_res[i])
        {
            delete[] hmac_res;
            return false;
        }
    delete[] hmac_res;
    return true;
}
/*
writeFileHmac:写入HMAC值
hashtype:哈希模式
fp:文件指针
hashMark:开始hash的地址
writeMark:写入Hmac的地址
fsize:文件大小
*/
void hmac::writeFileHmac(u8_t hashtype, FILE *fp, u8_t *key, u8_t hashMark, u8_t writeMark, size_t fsize)
{
    fseek(fp, hashMark, SEEK_SET);
    getres(hashtype, key, fp, fsize);
    fseek(fp, writeMark, SEEK_SET);
    fwrite(hmac_res, 1, length, fp);
    delete[] hmac_res;
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
    Hashmaster *hm = hf.getHasher(HashFactory::SHA1);
    hm->getStringHash(r_buf, strlen((const char *)r_buf), iv);
    for (int i = 1; i < num; ++i)
        hm->getStringHash(iv + (20 * (i - 1)), 20, iv + (20 * i));
    delete hm;
}
/*
getIV:获取初始向量(从文件)
fp:文件指针
iv:初始向量数组
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
    u64_t mn = Magic_Num;
    fwrite(&mn, 1, 8, out);
    fwrite(&ctype, 1, 1, out);
    fwrite(&htype, 1, 1, out);
    fwrite(padding, 1, PADDING, out);
    for (int i = 0; i < num; ++i)
        fwrite(iv + (20 * i), 1, 20, out);
}
/*
checkType:检查加密和哈希模式
*/
void FileHeader::checkType()
{
    fseek(fp, FILE_MODE_MARK, SEEK_SET);
    fread(&ctype, 1, 1, fp);
    fread(&htype, 1, 1, fp);
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
checkHmac:获得HMAC
len:hmac长度
return:HMAC地址
*/
u8_t *FileHeader::getHmac(u8_t len)
{
    fseek(fp, FILE_HMAC_MARK, SEEK_SET);
    int sum = fread(hash, 1, len, fp);
    if (sum != len)
        return NULL;
    return hash;
}

/*################################
  结果打印辅助函数
################################*/
void AbsResultPrint::resetPercentage()
{
    acc_size = 0;
    std::cout << "\r\n";
}
/*
printtask:打印任务
name:任务名
*/
void ResultPrint::printtask(std::string name)
{
    strlog("Task:", name);
}
/*
printinv: 打印非法
return: 返回值
*/
u8_t ResultPrint::printinv(const u8_t ret)
{
    strlog("Invalid values:", std::to_string(ret));
    return ret;
}
/*
createTimer:创建定时器
name:定时器名
return:返回的定时器
*/
Timer *ResultPrint::createTimer(string name)
{
    Timer *timer = new Timer;
    timer->name = name;
    timer->start = system_clock::now();
    return timer;
}

/*
printtime: 打印时间
totalTime: 总时间
*/
void ResultPrint::printTimer(Timer *timer)
{
    auto end = system_clock::now();
    auto totalTime = duration_cast<microseconds>(end - timer->start);
    strlog(timer->name + " : ", std::to_string(double(totalTime.count()) * microseconds::period::num / microseconds::period::den) + "s");
    delete timer;
}
/*
printenc: 打印加密结果
*/
void ResultPrint::printenc()
{
    strlog("Result:", "Encryption is over!");
    over = true;
}
/*
printres: 打印解密结果
res: 解密结果
*/
void ResultPrint::printresv(int res)
{
    std::string resstr = "Result:";
    if (res <= 0)
        strlog(resstr, "Verification passed!");
    else if (res == 1)
        strlog(resstr, "Input file is too short.");
    else if (res == 2)
        strlog(resstr, "Wrong key or File not complete.");
    else if (res == 3)
        strlog(resstr, "Aes / hash mode not match.");
    else if (res == 4)
        strlog(resstr, "Wrong magic number.");
    else
        strlog(resstr, "Unknown res number: " + std::to_string(res));
    over = true;
}
void ResultPrint::printresd(int res)
{
    if (res <= 0)
    {
        strlog("Result:", "Decryption is over!");
        over = true;
    }
    else
        printresv(res);
}
/*
printctype:打印加密模式
type:模式码
*/
void ResultPrint::printctype(u8_t type)
{
    std::string name = to_string(type) + "/" + AesFactory::getName(type);
    strlog("Crypt Mode:", name);
}
/*
printctype:打印哈希模式
type:模式码
*/
void ResultPrint::printhtype(u8_t type)
{
    std::string name = to_string(type) + "/" + HashFactory::getName(type);
    strlog("Hash Mode:", name);
}
/*
printpercentage:打印加载进度
name:进度名
percent:百分比
*/
void ResultPrint::printpercentage(std::string name, size_t now_size, size_t total_size)
{
    acc_size += now_size;
    this->total_size = total_size;
#ifndef GUI_ON
    std::cout << std::setw(5) << name << " loaded ";
    double percentage = 100 * ((double)acc_size / (double)total_size);
    const int barWidth = 50; // 进度条的总宽度
    std::cout << "[";
    int pos = round(barWidth * percentage / 100.0);
    for (int i = 0; i < barWidth; ++i)
    {
        if (i < pos)
            std::cout << "=";
        else if (i == pos)
            std::cout << ">";
        else
            std::cout << " ";
    }
    std::cout << "] " << std::setw(12) << std::fixed << std::setprecision(2) << percentage << " %\r";
    std::cout.flush();
#endif
}