# 数据加密解密程序

作者：闻嘉迅  
日期：2023.12.30 (最后修改)  
版本：v3.0.0 

**默认4线程,ECB加密模式**  
**处理速度可达80MB/s以上**  
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
- 8B-27B:HMAC-SHA1值        
- 28B-文件结尾:IV和加密后的文件数据

## 文件结构

- **wencry:项目文件夹**  
  - main.cpp:主函数   
  - config.h.in:配置文件  
  - **valget:获取参数包相关文件夹**
    - getval.h:获取参数包的头文件  
    - getval1.cpp:负责获取用户输入操作参数
    - getval2.cpp:负责获取控制台操作参数
    - **base64:base64转换文件夹**
      - base64.h:十六进制序列与base64编码的相互转换
      - base64.cpp:负责进行base64的编码和解码   
  - **kernel:加解密核心文件夹**
    - execval.h:接收参数包进行操作的头文件
    - execval.cpp:负责根据获取的参数选择操作执行  
    - **cryptfile:加解密函数文件夹**
      - cry.h:加解密流程相关的头文件  
      - decry.cpp:负责整体解密流程  
      - encry.cpp:负责整体加密流程
      - hmac.h:生成和校验HMAC的头文件
      - hmac.cpp:生成和校验HMAC  
      - **mcry:多线程进行aes加解密函数的文件夹**
        - multicry.h:多线程进行aes加解密的相关头文件
        - multicry.cpp:多线程进行aes加解密的函数实现
        - **aesmode:应用多种aes加密模式加密器的文件夹**
          - aesmode.h:不同模式的aes加密器的相关头文件
          - aesmode.cpp:不同模式的aes加密器的实现
          - **aes:进行128bitaes加解密和密钥处理的文件夹**
            - aes.h:AES加解密相关的头文件  
            - de_aes.cpp:负责AES解密的各流程  
            - en_aes.cpp:负责AES加密的各流程   
            - key.cpp:负责生成密钥  
            - state.h:加解密所需的结构体
            - **utils:通用头文件**  
              - macro.h:加解密所需的宏定义
              - tab.h:加解密所需的数表
        - **MBG:多线程缓冲区组的文件夹**
          - buffer.h:IO缓冲区的头文件  
          - buffer.cpp:实现IO缓冲区  
          - multi_buffergroup.h:多线程缓冲区组的相关头文件 
          - multi_buffergroup.cpp:多线程缓冲区组的实现
      - **sha1:sha1哈希函数文件夹**
        - sha1.h:进行sha1哈希相关的头文件  
        - sha1.cpp:负责产生sha1哈希的流程  
        - sha1subclass.cpp:通过文件和字符串获取哈希的实现  
        - **shabuf:哈希缓冲区文件夹**
          - shabuffer.h:哈希输入缓冲区头文件  
          - shabuffer.cpp:哈希输入缓冲区的实现
    - **resprint:打印操作结果文件夹**
      - resprint.h:打印操作结果的函数
      - resprint.cpp:结果打印的实现 
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
    - testsmode.cpp:不同模式下文件加解密测试  
    - testbig1.cpp:大文件加解密测试
    - testspeed.cpp:文件加密速度测试

具体函数和结构体作用与解释参阅源代码注释.  

## 使用方法

**创建构建目录**  
使用`mkdir ./build`命令创建构建目录,`cd ./build`命令进入构建目录.  
**构建并编译**  
使用`cmake ..`构建,`make`命令进行编译.  
**测试**
在项目编译后使用`ctest`命令进行测试.  
(若想关闭测试则需在根目录`CMakeLists.txt`中关闭`BUILD_TEST`选项.)  

**以下操作均在./build目录下进行**
### 加密

直接使用`./Wencry`命令，按提示进行操作  
加密后会生成`out.wenc`文件  

使用`./Wencry -e [fin] [mode] [code] [fout]`命令进行加密  
其中 -e 代表加密选项 fin 为输入文件的路径 mode 为加密模式(参见加密原理部分) code 为ase64编码后的16字节16进制数(编码后共24位),若输入G则为程序生成 fout 为输出文件名，缺省为 fin 值.  

加密完毕后会生成名为 [fout].wenc 的加密文件.

### 验证

直接使用`./Wencry`命令,按提示进行操作

使用`./Wencry -v [fin] [code]`命令进行验证  
其中 -v 代表验证选项 fin 为输入文件的路径 mode 为加密模式(参见加密原理部分) code 为base64编码后的16字节16进制数(编码后共24位).  

若密码无误且文件完整则会显示`File verified!`.  

### 解密

直接使用`./Wencry`命令,按提示进行操作

使用`./Wencry -d [fin] [mode] [code] [fout]`命令进行加密  
其中 -d 代表解密选项 fin 为输入文件的路径 code 为base64编码后的16字节16进制数(编码后共24位), fout 为输出文件名,缺省为 [fin].wdec .

解密完毕后若无误则会生成名为 fout 的还原文件.  

### 版本查看  

输入`./Wencry -V`命令,可显示版本和构建时间.  

## 多线程  
 
若想改变线程数量,则可改变`def.h`中的宏`THREADS_NUM`的值.  

**多线程原理**  
我们针对占运行时间近八成的aes加解密部分进行多线程处理,极大提高了运行效率.  
针对多线程运行的特性,将单独的缓冲区打包成多线程缓冲区组(以下简称MBG),即代码中的`buffergroup`类.具体来说在MBG的构造函数中会预先加载各缓冲区的数据.每个线程会根据独有的id访问相应缓冲区的数据.若数据处理完毕,则会调用MBG的`update_lst`尝试进行缓冲区更新.在函数`update_lst`中, 会首先检查当前的请求id是否和MBG中的成员turn相等,其中turn的取值为0~(size-1),指示当前MBG中应插入输出文件的缓冲区索引.若为真,则可进行更新,即将旧数据插入输出文件并从输入文件获取新数据;否则休眠等待.在更新完毕后turn的取值会更新:`turn = (turn + 1) % size;`即指示下一个应插入的缓冲区,并通知所有休眠的线程.以上两个动作均被封装在宏`COND_WAIT`和`COND_RELEASE`中.    
文件读取的最后一个缓冲区块往往是不全的,在处理完成这样的块后MBG中的`judge_over`函数会将已写完的数据写入到输出文件并使该线程退出.而若更新时读取到了空数据(即没有数据写入该缓冲区),则`update_lst`函数会返回`false`使该线程退出.     

各个线程的处理流程如下:  
```cpp
void multiruncrypt_file(u8_t id, multicry_master *cm) {
  while (true) {
    u8_t *block = cm->bg.require_buffer_entry(id);
    if (block == NULL) {
      if (cm->bg.judge_over(id) || (!cm->bg.update_lst(id)))
        break;
    } else
      cm->process(id, block);
  }
  return;
}
```
首先尝试获取待处理的缓冲区单元,若不为空则进行处理,否则交由MBG判断是否已经读写完毕,若为真则进行相应处理后退出,否则尝试更新该缓冲区,若成功则继续循环,否则退出.  


详细过程参阅相关代码.  

## 加密流程更新

2.9,3.0版本更新大幅改动了加密流程,通过增加HMAC,AES加密模式,pcks7填充等方法进一步增加了安全性.  

### HMAC
HMAC,即哈希消息验证码,是对密文和密钥的一个信息摘要,通过校验HMAC可以同时确定密钥和密文是否正确,未来还将支持MD5等其他哈希算法.  

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
在加密信息尾部处理时,经常会遇到填充问题,此前采用的0填充需另行记录尾部字节数(即tail),较为繁琐也不安全.更新后的加密采用了较为流行的pcks7填充方式,使加解密更简洁安全性更高.  

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
*v3.0 新增:可选用不同的加密模式,采用pcks7进行填充,增加大量测试用例以测试核心组件的正确性,修复部分bug.*  