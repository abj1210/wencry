#ifndef MKT
#define MKT

#include "hashmaster.h"
#include "sha_ni.h"
#include <stack>
#include <queue>
#include <vector>
#include <mutex>


/*
哈希函数工厂类(类型列表单源见 valhelper/modes.h 的 HashType 枚举)
*/
class HashFactory
{
public:
  /*
  getType:根据数字返回哈希类型
  type:输入的数字
  return:返回的类型(非法返回 HT_COUNT 哨兵)
  */
  static HashType getType(u8_t type){
    switch (type)
    {
    case HT_SHA1:
        return HT_SHA1;
    case HT_MD5:
        return HT_MD5;
    case HT_SHA256:
        return HT_SHA256;
    default:
        return HT_COUNT;
    }
    };
  /*
  getHasher:根据哈希类型返回相应的算法
  type:哈希类型
  return:返回的哈希类
  */
  HashMaster *getHasher(HashType type){
    switch (type)
    {
    case HT_SHA1:
        return new Sha1Ni();
    case HT_MD5:
        return new Md5Hash();
    case HT_SHA256:
        return new Sha256Ni();
    default:
        return NULL;
    }
    };
};

/*
Hmac:计算HMAC类
HMAC 结构(标准 RFC 2104):
HMAC = H( (K xor opad) || H( (K xor ipad) || 数据 ) ),其中 ipad=0x36,opad=0x5c。
Hmac提供基于内存缓冲区的一次性HMAC计算(getHmac),支持通过 prefix 参数
进行域分离(如 Merkle 叶前缀 "L" 与根前缀 "R")。
底层增量原语 initHash/feedHash/finalizeHash 负责逐步喂入数据并输出摘要,
一次性接口 getHmac 内部复用这些原语。
*/

class Hmac
{
  static const u8_t ipad = 0x36, opad = 0x5c;
  HashFactory hf;
  u8_t *hmac_res, length;
  /* computeHmac:计算一次性HMAC并把结果存入 hmac_res(private) */
  void computeHmac(u8_t hashtype, u8_t *key, const u8_t *buffer, size_t bufsize,const u8_t *prefix=NULL, size_t prefix_len=0);

  // 增量HMAC(一次性路径内部复用)使用的状态
  HashMaster *hashmaster;
  HashMaster::blockFast_t blockFast; // 热路径整块处理函数(避免每块虚调用)
  u8_t *key1, *h1;
  u8_t accum[64];
  u8_t block_len, accum_len;

  void clearIncremental();

public:
  Hmac();
  ~Hmac();
  void getHmac(u8_t hashtype, u8_t *key, const u8_t *buf, u8_t *hmac_out,size_t bufsize = 0, u8_t *prefix=NULL, size_t prefix_len=0);
  /*
  增量HMAC原语(被 getHmac 内部复用)
  initHash:初始化,喂入ipad块与可选prefix
  feedHash:喂入数据块
  finalizeHash:完成计算,结果存于hmac_res
  matchResult:finalizeHash 后与给定摘要比较
  */
  void initHash(u8_t hashtype, u8_t *key, const u8_t *prefix, size_t prefix_len);
  void feedHash(const u8_t *data, size_t len);
  void finalizeHash();
  bool matchResult(const u8_t *expected, u8_t len, u8_t *hmac_res = NULL) const;
};

/*
MerkleTreeMaster:MerkleTree生成类
MerkleTreeMaster负责merkle tree的生成，其接受各个数据块的叶Hmac并将其按二叉树合并为节点哈希，检查并输出top哈希。
加入叶Hmac时支持乱序输入，乱序的Hmac在优先队列中进行同步，再输出到mt栈中进行合并。
在mt栈中，对栈内互为伙伴的叶Hmac、节点哈希进行合并，构建merkle tree。
输入结束后，对mt栈中残留的节点哈希进行统一合并，得出top哈希，并输出统计的Hmac块数。
注意：在多线程模式时，addBlockHmac函数和getTopHash为原子操作。
注意：该类不负责Hmac操作，需要额外进行Hmac，且输出的结果为top哈希，仍需要额外的Hmac操作得到根Hmac。
*/
class MerkleTreeMaster{
    /* MTNode:树节点,记录覆盖的块区间 [blk_head, blk_tail) 与该节点的哈希值 */
    class MTNode{
        public:
            size_t blk_head, blk_tail;
            std::vector<u8_t> hash_load;
            MTNode(size_t hash_length) : blk_head(0), blk_tail(0), hash_load(hash_length) {}
            MTNode(size_t blk_id, size_t hash_length) : blk_head(blk_id), blk_tail(blk_id+1), hash_load(hash_length) {}
            bool operator>(const MTNode& o) const { return blk_head > o.blk_head; }
    };
    size_t hash_size, blk_cnt;
    std::stack<MTNode> mtstack;
    std::priority_queue<MTNode, std::vector<MTNode>, std::greater<MTNode> > sync_queue;
    std::mutex mtx;
    HashMaster *hashmaster;
    u8_t prefix[0x1000];
    /* judgeBuddy:判断两节点是否可合并为规范兄弟(左右跨度相同且边界对齐) */
    bool judgeBuddy(MTNode& nodel, MTNode& noder);
    /* synchronizeStack:当堆顶块号续接栈尾时把块搬入栈 */
    bool synchronizeStack();
    /* hashMerge:持续合并栈顶可合并的兄弟节点 */
    void hashMerge();
    /* finalMerge:把残留节点自底向上合并到根 */
    void finalMerge();
    /* checkMerkleTree:校验树形合法(单根、队列空、覆盖 [0,blk_cnt)) */
    bool checkMerkleTree();
public:
    MerkleTreeMaster();
    ~MerkleTreeMaster();
    /* setHashType:设置哈希类型并重置全部合并状态(单次调用,需在添加块前完成) */
    void setHashType(u8_t hashtype);
    /* addBlockHmac:添加一块已计算的叶子HMAC(可按任意块号顺序调用) */
    void addBlockHmac(size_t blk_id, const u8_t *blk_hmac);
    /* getTopHash:完成合并并输出根哈希,成功返回块数,失败返回 (size_t)-1 */
    size_t getTopHash(u8_t * top_result);
    /* getHashSize:返回当前哈希类型的摘要字节长度 */
    size_t getHashSize(){return hashmaster->getHashLength();};
    /* getLeafPrefix:生成第 id 块叶子HMAC的域分离前缀 "L"+8字节小端块号(共9字节) */
    void getLeafPrefix(size_t id, u8_t *out);
    /* getPrefixLen:返回叶前缀长度(固定9字节) */
    size_t getPrefixLen(){return 9;};
    /* getRootPrefix:生成根HMAC的域分离前缀 "R"+8字节小端块数+各线程IV。
       返回内部缓冲(非线程安全,仅供根合并单线程阶段调用)。 */
    u8_t* getRootPrefix(size_t total_blocks, u8_t * iv, u8_t n);
};

#endif
