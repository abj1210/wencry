# 数据加密解密程序

作者：闻嘉迅  
日期：2024.6.27 (最后修改)  
版本：v3.6.2

**默认4+1线程,CBC加密模式**  
**处理速度可达50MB/s以上**  
**内存占用小于80MB**   

## 加密原理

**加密**  
根据输入或随机数计算IV
根据选定的加密模式,使用密钥和IV(初始向量)进行AES128加密  
根据密文和密钥生成HMAC
得到最终的加密文件  

**解密**  
先检查魔数,确定为正确加密后的文件  
再提取文件的HMAC与计算的HMAC比较,确保文件完整  
提取IV  
最后根据加密模式对文件进行AES128解密  
得到解密后的文件  

**加密文件结构**  
加密后的文件带有后缀.wenc,其结构如下:
- 0B-7B:魔数 
- 8B-10B:模式 
- 10B-47B:HMAC值        
- 48B-文件结尾:IV和加密后的文件数据

## 文件结构

- **wencry:项目文件夹**  
  - main.cpp:主函数   
  - config.h.in:配置文件  
  - **valget:获取参数包相关文件夹**
    - getval.h:获取参数包的头文件  
    - getopts.cpp:负责获取控制台操作参数
    - getval1.cpp:负责获取用户输入操作参数
    - information.cpp:负责打印版本信息和帮助信息
    - **base64:base64转换文件夹**
      - base64.h:十六进制序列与base64编码的相互转换
      - base64.cpp:负责进行base64的编码和解码   
  - **kernel:加解密核心文件夹**  
    - cry.h:加解密流程相关的头文件  
    - cry.cpp:负责整体加解密流程  
    - fheader.cpp:负责文件头的生成和验证流程
    - **multi_aes:多线程进行aes加解密函数的文件夹**
      - multicry.h:多线程进行aes加解密的相关头文件
      - multicry.cpp:多线程进行aes加解密的函数实现
      - multi_buffergroup.h:多线程缓冲区组的相关头文件 
      - multi_buffergroup.cpp:多线程缓冲区组的实现
      - **aesmode:应用多种aes加密模式加密器的文件夹**
        - aesmode.h:不同模式的aes加密器的相关头文件
        - aesmode.cpp:不同模式的aes加密器的实现
        - aes.h:AES加解密相关的头文件  
        - aes.cpp:负责AES加解密的各流程  
        - tab.h:加解密所需的数表
    - **hash:哈希函数文件夹**
      - sha1.cpp:负责产生sha1哈希的流程  
      - md5.cpp:负责产生md5哈希的流程 
      - hashmaster.h:产生不同类型哈希的头文件
      - hashmaster.cpp:产生不同类型哈希类的实现  
      - hashbuffer.h:哈希输入缓冲区头文件  
      - hashbuffer.cpp:哈希输入缓冲区的实现
  - **test:测试文件夹**
    - testutil.h:基础组件测试相关函数的头文件
    - testutil.cpp:基础组件测试相关函数的实现
    - test.h:测试相关函数的头文件
    - test.cpp:测试相关函数的实现
    - testutest.cpp:testutil函数测试
    - testsha1.cpp:sha1哈希测试
    - testaes.cpp:单块aes测试
    - testbase64.cpp:base64编码测试
    - testhmac.cpp:HMAC编码测试
    - testECB.cpp:ECB模式下多块aes测试
    - testCBC.cpp:CBC模式下多块aes测试
    - testCTR.cpp:CTR模式下多块aes测试
    - testCFB.cpp:CFB模式下多块aes测试
    - testOFB.cpp:OFB模式下多块aes测试
    - testsmall.cpp:小文件加解密测试
    - testsmode.cpp:不同加密模式下文件加解密测试  
    - testshash.cpp:不同哈希模式下文件加解密测试  
    - testbig.cpp:大文件加解密测试
    - testspeed.cpp:文件加密速度测试

具体函数和结构体作用与解释参阅源代码注释.  

## 使用方法

**创建构建目录**  
使用`mkdir ./build`命令创建构建目录,`cd ./build`命令进入构建目录.  
**构建并编译**  
使用`cmake -DCMAKE_BUILD_TYPE=[Debug/Release] ..`构建Debug或Release版本,`make`命令进行编译.  
**测试**
在项目编译后使用`ctest`命令进行测试.  
(若想关闭测试则需在根目录`CMakeLists.txt`中关闭`BUILD_TEST`选项.)  

**以下操作均在./build目录下进行**  

**若在无参数下执行，则可根据提示完成操作**  
**命令行参数模式的介绍如下**

### 选择模式

- `-e`/`--encode` 为加密模式
- `-d`/`--decode` 为解密模式
- `-v`/`--verify` 为验证模式
- `-V`/`--version` 为查看版本
- `-h`/`--help` 为查看帮助

### 参数设置

- `-i`/`--input` + `[inputfile]` 指示输入文件路径
- `-o`/`--output` + `[outputfile]` 指示输出文件路径，缺省为输入文件路径+".wenc"后缀
- `-k`/`--key` + `[key]` 指示ase64编码后的16字节16进制密钥(编码后共24位) ，缺省为随机生成的密钥
- `--cmode` + `[mode]` 指示加密模式(参见加密原理部分)  
- `--hmode` + `[mode]` 指示哈希模式(参见HMAC部分) 
- `-n`/`--no_echo` 此选项表示隐藏处理信息

### 示例

- 加密: ./Wencry -e -i ../a.mp4 --cmode 2 -o ../a.mp4.wenc
- 解密: ./Wencry -d -i ../a.mp4.wenc --cmode 2 -o ../aa.mp4 -k Z8Zpc1HSuwpzbqr8vvjRg==

## 多线程  
 
若想改变线程数量,则可改变`def.h`中的宏`THREADS_NUM`的值.  
相关代码位于`multicry.cpp`和`multi_buffergroup.cpp`中.  

- **多线程原理**  
我们针对占运行时间近八成的aes加解密部分进行多线程处理,极大提高了运行效率.  
针对多线程运行的特性,将单独的缓冲区打包成多线程缓冲区组(以下简称MBG),即代码中的`buffergroup`类.具体来说在MBG的构造函数中会预先加载各缓冲区的数据.每个处理线程会根据独有的id访问相应缓冲区的数据.而一个独立的缓冲区维护线程将会负责更新缓冲区的数据.  
- **处理线程**  
在一次加/解密过程中会运行多个处理线程,负责进行并发数据处理。每个处理线程都有一个唯一的`id`,用来从MBG中获取相应缓冲区的数据,并对获取的数据进行处理.  
代码如下:
```cpp
void multiruncrypt_file(u8_t id, Aesmode &mode)
{
  buffergroup *iobuffer = buffergroup::get_instance();
  u8_t *block = iobuffer->require_buffer_entry(id);
  while (block != NULL)
  {
    mode.runcry(block);
    block = iobuffer->require_buffer_entry(id);
  }
};
```
- **缓冲区维护线程**  
该线程负责维护MBG的数据,并进行更新.具体来说,该线程会轮流访问并更新相应的缓冲区,为处理线程提供新的数据.
代码如下:
```cpp
void buffergroup::run_buffer()
{
  u8_t cnt = size;
  while (cnt > 0)
  {
    if (!ctrl[turn].cmpstate(INV))
    {
      auto locker = ctrl[turn].wait_update();
      if (ctrl[turn].cmpstate(UPDATING) && buflst[turn].buffer_over())
        final_update();
      buffer_update();
      if (ctrl[turn].cmpstate(INV))
        cnt--;
      locker.unlock();
    }
    turn = turn == (size - 1) ? 0 : turn + 1;
}
```
- **线程间协作**  
上述两种线程间的协作通过各个缓冲区对于的`bufferctrl`类实例完成,该类指示了相应缓冲区的状态,并提供了相应的条件变量来进行线程间同步.  
具体来说,当处理线程调用`require_buffer_entry`函数时,MBG会首先检查数据是否读完,若读完则更改状态为`UPDATING`并唤醒缓冲区维护线程.随后,检查相应的缓冲区的状态.若状态为`EMPTY`或`UPDATING`则表明该缓冲区数据尚未准备好,此时该线程将被阻塞并等待缓冲区维护线程将数据准备好.  
另一方面,在缓冲区维护线程循环访问缓冲区时,会先检查缓冲区状态,若为`INV`则跳过该缓冲区;而若为`READY`则表明缓冲区尚不需要更新,此时该线程将阻塞.当该线程被相应的处理线程唤醒后,会根据具体情况处理该缓冲区:若该缓冲区还有数据需装载,则处理后状态更改为`READY`;否则说明缓冲区已处理完毕,状态会更改为`INV`.随后唤醒相应的处理队列继续工作.  

详细过程参阅相关代码.  

## 加密流程更新

2.9,3.0版本更新大幅改动了加密流程,通过增加HMAC,AES加密模式,pcks7填充等方法进一步增加了安全性.  

### HMAC
HMAC,即哈希消息验证码,是对密文和密钥的一个信息摘要,通过校验HMAC可以同时确定密钥和密文是否正确,未来还将支持MD5等其他哈希算法.  
**HMAC的哈希模式**  
  - 0:sha1
  - 1:md5
  - 2:sha256

### AES加密模式
早期版本的加密方式为确定性加密,安全性较差,易遭到选择明文攻击.此次更新引入了五种不同的AES加密模式:  
  - 0:电子密码本ECB  
  - 1:密码块链CBC  
  - 2:计数器模式CTR  
  - 3:密文反馈CFB  
  - 4:输出反馈OFB  

进行加解密时可输入相应的序号(命令行参数中的mode)以选择相应的加密方式,若输入不在0-4之间,择默认选择0号ECB模式(个人不建议选择0号).  
以上五种模式除ECB外均为非确定性加密,需要初始向量IV.在命令行模式中可以手动输入字符串以生成IV(不建议重复使用相同的字符串,会造成安全风险).在命令行参数模式下系统会自动生成随机的IV.  

***!!!重要:加解密同一文件时一定要选择相同的加密模式,否则会解密失败!!!***

### pcks7填充  
在加密信息尾部处理时,经常会遇到填充问题,此前采用的0填充需另行记录尾部字节数(即tail),较为繁琐也不安全.更新后的加密采用了较为流行的pcks7填充方式,使加解密更简洁,安全性更高.  

## 更新日志

*v1.1 新增:以base64编码输入密码,并重构了部分代码.*  
*v1.2 新增:git actions用于提交自动测试.*  
*v1.3 新增:删除部分冗余代码并重构部分代码以提高效率.*  
*v1.4 新增:改变部分代码结构以提高效率.*
*v1.5 新增:重写buffer部分,为未来支持多线程提供条件.*  
*v1.6 新增:重写部分核心函数,小幅提高运行效率.(1.6.1 重写makefile文件和部分核心代码)*  
*v1.7 新增:修复了有关IO缓冲区的bug,大幅减小了运行时的内存(小于50MB).并添加部分注释.(1.7.1 1.7.2 重写核心函数以提高运行效率)*  
*v1.8 新增:更改文件结构和makefile文件,提高核心代码运行效率.*  
*v1.9 新增:增加了加密文件验证的功能.(1.9.1 git actions中增加速度测试代码)*  
*v1.10 新增:改变为c++语言实现.(1.10.1 改变部分文件结构 1.10.2 重构部分代码以提高执行效率)*  
*v1.11 新增:重写IO缓冲区以减小内存占用.*  
*v2.0 新增:支持多线程模式.(2.0.1 改变并发中同步结构)*  
*v2.1 新增:改变加密文件头的格式.(2.1.1 2.1.2 改变多线程实现以支持多平台)*  
*v2.2 新增:部分函数改用类进行包装,重写多线程同步逻辑.(2.2.1 2.2.2 重构部分代码)*  
*v2.3 新增:增加随机缓冲哈希,使得在同文件同密钥情况下加密仍能得到不同的加密文件,提高了安全性.*  
*v2.4 新增:修复了windows环境下多线程同步失败的bug.*   
*v2.5 新增:修复了与RBH相关的bug.(2.5.1 改变文件结构)*  
*v2.6 新增:采用cmake自动构建和ctest自动测试.(2.6.1 增加自动速度测试版本查看并修复已知bug 2.6.2 2.6.3 修改文件结构)*  
*v2.7 新增:改变部分功能的实现和文件结构(2.7.1 更改部分文件以兼容visual stdio 2.7.2 改变sha1哈希类的实现).*  
*v2.8 新增:修改并发函数和哈希函数(2.8.1 2.8.2 2.8.3 更改部分函数实现).*  
*v2.9 新增:使用HMAC-SHA1进行文件验证.*  
*v3.0 新增:可选用不同的加密模式,采用pcks7进行填充,增加大量测试用例以测试核心组件的正确性,修复部分bug.(3.0.1 改变哈希部分结构,用以支持多种哈希模式. 3.0.2 优化文件结构)*  
*v3.1 新增:采用标准化的命令行解析函数来获取参数，优化文件结构(3.1.1 增加-n选项 3.1.2 重构部分代码).*  
*v3.2 新增:修复已知bug,更改文件头结构以便未来兼容不同哈希类型的hmac.*  
*V3.3 新增:可选择使用md5的hmac(3.3.1 重构部分代码并添加注释,重写时间测量逻辑,增加cmake编译选项).*
*V3.4 新增:采用多种设计模式进行代码优化(3.4.1优化部分处理过程输出 3.4.2 使用设计模式进行进一步优化).*
*V3.5 新增:修复已知bug,更新输出界面,采用统一格式输出结果.*
*V3.6 新增:更改多线程实现,提高效率.可选择使用sha256的hmac(v3.6.1修复部分bug, v3.6.2改变部分函数实现).*