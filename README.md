# 数据加密解密程序

作者：闻嘉迅  
日期：2023.12.5 (最后修改)  
版本：v2.6.2  

**默认4线程模式**  
**处理速度可达80MB/s以上**  
**内存占用小于80MB**  

## 加密原理

**加密**  
输入随机缓冲数组并哈希
对于目标文件与随机缓冲哈希进行异或后进行AES128加密  
对加密后的信息,随机缓冲哈希和密钥进行sha1哈希操作  
得到最终的加密文件  

**解密**  
先检查魔数,确定为正确加密后的文件  
再对密钥进行哈希比较,确定为正确的密钥  
再对文件进行哈希比较,确定文件未被篡改 
提取随机缓冲哈希  
最后对文件件与随机缓冲哈希进行异或后进行AES128解密  
得到解密后的文件  

**加密文件结构**  
加密后的文件带有后缀.wenc,其结构如下:
- 0B-6B:魔数  
- 7B-26B:密钥的sha1哈希值  
- 27B-46B:加密后文件的哈希值  
- 47B:源文件字节数与16取模后的数值  
- 48B-67B:随机缓冲哈希  
- 68B-文件结尾:加密后的文件数据

## 文件结构

- **wencry:项目文件夹**  
  - main.cpp:主函数   
  - **valget:获取参数包相关文件夹**
    - base64.h:十六进制序列与base64编码的相互转换
    - base64.cpp:负责进行base64的编码和解码  
    - getval.h:获取参数包的头文件  
    - getval.cpp:负责获取操作参数  
  - **kernel:加解密核心文件夹**
    - execval.h:接收参数包进行操作的头文件
    - execval.cpp:负责根据获取的参数选择操作执行  
    - **src:加解密函数文件夹**
      - cry.h:加解密流程相关的头文件  
      - decry.cpp:负责整体解密流程  
      - encry.cpp:负责整体加密流程  
      - **crypt:进行aes加解密函数的文件夹**
        - multicry.h:多线程进行aes加解密的相关头文件
        - multicry.cpp:多线程进行aes加解密的函数实现
        - **aeskey:进行128bitaes加解密和密钥处理的文件夹**
          - aes.h:AES加解密相关的头文件  
          - de_aes.cpp:负责AES解密的各流程  
          - en_aes.cpp:负责AES加密的各流程  
          - key.h:密钥生成相关头文件  
          - key.cpp:负责生成密钥  
          - state.h:state结构体的定义 
          - **include:通用头文件**
            - macro.h:aes和密钥所需的宏
            - tab.h:aes和密钥所需数表 
        - **MBG:多线程缓冲区组的文件夹**
          - buffer.h:IO缓冲区的头文件  
          - iobuffer.cpp:实现IO缓冲区  
          - multi_buffergroup.h:多线程缓冲区组的相关头文件 
          - multi_buffergroup.cpp:多线程缓冲区组的实现
      - **sha1:sha1哈希函数文件夹**
        - macro.h:哈希相关宏
        - shabuffer.h:哈希输入缓冲区头文件  
        - shabuffer.cpp:哈希输入缓冲区的实现
        - sha1.h:进行sha1哈希相关的头文件  
        - sha1.cpp:负责产生sha1哈希的流程  
  - **test:测试文件夹**
    - test.h:测试相关函数的头文件
    - test.cpp:测试相关函数的实现
    - testsmall1.cpp testsmall2.cpp:小文件加解密测试  
    - testbig1.cpp:大文件加解密测试

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

使用`./Wencry -e [fin] [code] [fout]`命令进行加密  
其中 -e 代表加密选项 fin 为输入文件的路径 code 为ase64编码后的16字节16进制数(编码后共24位),若输入G则为程序生成 fout 为输出文件名，缺省为 fin 值.  

加密完毕后会生成名为 [fout].wenc 的加密文件.

### 验证

直接使用`./Wencry`命令,按提示进行操作

使用`./Wencry -v [fin] [code]`命令进行验证  
其中 -v 代表验证选项 fin 为输入文件的路径 code 为base64编码后的16字节16进制数(编码后共24位).  

若密码无误且文件完整则会显示`File verified!`.  

### 解密

直接使用`./Wencry`命令,按提示进行操作

使用`./Wencry -d [fin] [code] [fout]`命令进行加密  
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
```c
void multiencrypt_file(int id, u8_t * tailin) {
  encryaes aes(keyh);
  while (true) {
    state_t *block = (state_t *)bg->require_buffer_entry(id);
    if (block == NULL) {
      * tailin = bg->judge_over(id, 16);
      if ((* tailin != 0)||(!bg->update_lst(id))) 
        break;
    } else
      aes.encryaes_128bit(*block);
  }
}
```
首先尝试获取待处理的缓冲区单元,若不为空则进行处理,否则交由MBG判断是否已经读写完毕,若为真则进行相应处理后退出,否则尝试更新该缓冲区,若成功则继续循环,否则退出.  


详细过程参阅相关代码.  

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
*v2.6 新增:采用cmake自动构建和ctest自动测试.(2.6.1 增加自动速度测试版本查看并修复已知bug 2.6.2 修改文件结构)*  