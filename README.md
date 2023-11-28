# 数据加密解密程序

作者：闻嘉迅  
日期：2023.11.28 (最后修改)  
版本：v2.1  

**默认4线程模式**  
**处理速度可达100MB/s以上**  
**内存占用小于80MB**  

## 加密原理

**加密**  
对于目标文件进行AES128加密  
对加密后的信息和密钥进行sha1哈希操作  
得到最终的加密文件  

**解密**  
先检查魔数,确定为正确加密后的文件  
再对密钥进行哈希比较,确定为正确的密钥  
再对文件进行哈希比较,确定文件未被篡改  
最后对文件进行AES128解密  
得到解密后的文件  

**加密文件结构**  
加密后的文件带有后缀.wenc,其结构如下:
- 0B-6B:魔数  
- 7B-26B:密钥的sha1哈希值  
- 27B-46B:加密后文件的哈希值  
- 47B:源文件字节数与16取模后的数值  
- 48B-文件结尾:加密后的文件数据

## 文件结构

- include:头文件  
    - util:通用的结构体和宏  
        - buffer.h:IO缓冲区的头文件  
        - def.h:宏定义  
        - struct.h:结构体  
        - tab.h:各种数表
    - aes.h:AES加解密相关的头文件
    - cry.h:加解密流程相关的头文件
    - key.h:密钥生成相关头文件
    - sha1.h:进行sha1哈希相关的头文件
    - multicry.h:多线程进行aes加解密的相关头文件
    - util.h:包含了util文件夹下的所有头文件 
    - wenctrl.h:main函数流程控制相关的头文件

- src:源代码
    - aesd.cpp:负责AES解密的各流程
    - aese.cpp:负责AES加密的各流程  
    - base64.cpp:负责进行base64的编码和解码  
    - buffer.cpp:实现IO缓冲区  
    - encry.cpp:负责整体加密流程
    - execval.cpp:负责根据获取的参数选择操作执行  
    - decry.cpp:负责整体解密流程
    - getval.cpp:负责获取操作参数
    - key.cpp:负责生成密钥
    - main.cpp:主函数
    - multicry.cpp:多线程进行aes加解密的函数实现
    - sha1.cpp:负责产生sha1哈希的流程
    
- test:测试代码和文件
    - test.c:测试正确性代码
    - test_file.c:测试运行效率的代码
    - testfile.txt t2.txt:测试文件

- bin:生成的二进制目标文件所在文件夹

具体函数和结构体作用与解释参阅源代码注释.  

## 使用方法

使用`make wencry`命令进行编译  
使用`make test_once`命令进行自动测试  
使用`make analysis`命令进行性能分析(此时应在F变量中加入`-pg`选项和分析文件)

### 加密

直接使用`./wencry`命令，按提示进行操作  
加密后会生成`out.wenc`文件  

使用`./wencry -e [fin] [code] [fout]`命令进行加密  
其中 -e 代表加密选项 fin 为输入文件的路径 code 为ase64编码后的16字节16进制数(编码后共24位),若输入G则为程序生成 fout 为输出文件名，缺省为 fin 值.  

加密完毕后会生成名为 [fout].wenc 的加密文件.

### 验证

直接使用`./wencry`命令,按提示进行操作

使用`./wencry -v [fin] [code]`命令进行验证  
其中 -v 代表验证选项 fin 为输入文件的路径 code 为base64编码后的16字节16进制数(编码后共24位).  

若密码无误且文件完整则会显示`File verified!`.  

### 解密

直接使用`./wencry`命令,按提示进行操作

使用`./wencry -d [fin] [code] [fout]`命令进行加密  
其中 -d 代表解密选项 fin 为输入文件的路径 code 为base64编码后的16字节16进制数(编码后共24位), fout 为输出文件名,缺省为 [fin].wdec .

解密完毕后若无误则会生成名为 fout 的还原文件.

### 多线程  

默认开启多线程,若想关闭多线程模式则可在`def.h`中取消对宏`MULTI_ENABLE`的定义.  
若想改变线程数量,则可改变`def.h`中的宏`THREADS_NUM`的值.  

**多线程原理**  
我们针对占运行时间近八成的aes加解密部分进行多线程处理,极大提高了运行效率.  
对于每个线程,其都拥有一个独立的缓冲区,正常状态下各个线程独立处理自身缓冲区内容.当该缓冲区内的数据全部处理完成后(即处理完成一个"缓冲区块"),则需要进行线程同步以保存和更新缓冲区内容.  
每当一个线程申请一个缓冲区块时,都会被分配一个独有值作为该缓冲区块的序列号,当该缓冲区块处理完毕后,该进程会检查该缓冲区块的序列号是否与输出文件需要的序列号相等.  
```cpp
    while(outputidx!=idxnow&&inputidx!=-1)
        pthread_cond_wait(&cond,&mutex);
```
若不相等则表示该缓冲区块暂时还不能放入输出文件中,进程进入休眠状态;若相等则表示为输出文件所需的缓冲区块,进程拷贝缓冲区块至输出文件,将输出文件需要的序列号加一,申请新的缓冲区块并唤醒其他正在休眠的线程以检查是否符合条件.  
```cpp
    outputidx++;
    if(inputidx==-1)flag=false;
    else idxnow=inputidx++;
    pthread_cond_broadcast(&cond);
```
当一个进程已经将输入文件读取完毕,则其将输入序列号更改为-1以表示输入结束,并唤醒其他正在休眠的线程.随后所有线程检查到输入序号为-1并退出线程,多线程处理结束.  
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
*v1.11 新增:重写IO缓冲区以减小内存占用*  
*v2.0 新增:支持多线程模式(2.0.1 改变并发中同步结构)*  
*v2.1 新增:改变加密文件头的格式*  
