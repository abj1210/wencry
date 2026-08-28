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
  Hashmaster *getHasher(HashType type){
    switch (type)
    {
    case HT_SHA1:
        return new sha1ni();
    case HT_MD5:
        return new md5hash();
    case HT_SHA256:
        return new sha256ni();
    default:
        return NULL;
    }
    };
};

/*
hmac:计算HMAC类
HMAC 结构(标准 RFC 2104):
HMAC = H( (K xor opad) || H( (K xor ipad) || 数据 ) ),其中 ipad=0x36,opad=0x5c。
hmac提供基于内存缓冲区的一次性HMAC计算(gethmac),支持通过 prefix 参数
进行域分离(如 Merkle 叶前缀 "L" 与根前缀 "R")。
底层增量原语 init_hash/feed_hash/final_hash 负责逐步喂入数据并输出摘要,
一次性接口 gethmac 内部复用这些原语。
*/

class hmac
{
  static const u8_t ipad = 0x36, opad = 0x5c;
  HashFactory hf;
  u8_t *hmac_res, length;
  /* getres:计算一次性HMAC并把结果存入 hmac_res(private) */
  void getres(u8_t hashtype, u8_t *key, const u8_t *buffer, size_t bufsize,const u8_t *prefix=NULL, size_t prefix_len=0);

  // 增量HMAC(一次性路径内部复用)使用的状态
  Hashmaster *hashmaster;
  Hashmaster::block_fast_t block_fast; // 热路径整块处理函数(避免每块虚调用)
  u8_t *key1, *h1;
  u8_t accum[64];
  u8_t block_len, accum_len;

  void clear_incr();

public:
  hmac();
  ~hmac();
  void gethmac(u8_t hashtype, u8_t *key, const u8_t *buf, u8_t *hmac_out,size_t bufsize = 0, u8_t *prefix=NULL, size_t prefix_len=0);
  /*
  增量HMAC原语(被 gethmac 内部复用)
  init_hash:初始化,喂入ipad块与可选prefix
  feed_hash:喂入数据块
  final_hash:完成计算,结果存于hmac_res
  match_result:final_hash 后与给定摘要比较
  */
  void init_hash(u8_t hashtype, u8_t *key, const u8_t *prefix, size_t prefix_len);
  void feed_hash(const u8_t *data, size_t len);
  void final_hash();
  bool match_result(const u8_t *expected, u8_t len, u8_t *hmac_res = NULL) const;
};

/*
MerkleTreeMaster:MerkleTree生成类
MerkleTreeMaster负责merkle tree的生成，其接受各个数据块的叶hmac并将其按二叉树合并为节点哈希，检查并输出top哈希。
加入叶hmac时支持乱序输入，乱序的hmac在优先队列中进行同步，再输出到mt栈中进行合并。
在mt栈中，对栈内互为伙伴的叶hmac、节点哈希进行合并，构建merkle tree。
输入结束后，对mt栈中残留的节点哈希进行统一合并，得出top哈希，并输出统计的hmac块数。
注意：在多线程模式时，add_block_hmac函数和get_top_hash为原子操作。
注意：该类不负责hmac操作，需要额外进行hmac，且输出的结果为top哈希，仍需要额外的hmac操作得到根hmac。
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
    Hashmaster *hashmaster;
    u8_t prefix[0x1000];
    /* judge_buddy:判断两节点是否可合并为规范兄弟(左右跨度相同且边界对齐) */
    bool judge_buddy(MTNode& nodel, MTNode& noder);
    /* synchronize_stack:当堆顶块号续接栈尾时把块搬入栈 */
    bool synchronize_stack();
    /* hash_merge:持续合并栈顶可合并的兄弟节点 */
    void hash_merge();
    /* final_merge:把残留节点自底向上合并到根 */
    void final_merge();
    /* check_mt:校验树形合法(单根、队列空、覆盖 [0,blk_cnt)) */
    bool check_mt();
public:
    MerkleTreeMaster();
    ~MerkleTreeMaster();
    /* set_hashtype:设置哈希类型并重置全部合并状态(单次调用,需在添加块前完成) */
    void set_hashtype(u8_t hashtype);
    /* add_block_hmac:添加一块已计算的叶子HMAC(可按任意块号顺序调用) */
    void add_block_hmac(size_t blk_id, const u8_t *blk_hmac);
    /* get_top_hash:完成合并并输出根哈希,成功返回块数,失败返回 (size_t)-1 */
    size_t get_top_hash(u8_t * top_result);
    /* get_hash_size:返回当前哈希类型的摘要字节长度 */
    size_t get_hash_size(){return hashmaster->gethlen();};
    /* get_leaf_prefix:生成第 id 块叶子HMAC的域分离前缀 "L"+8字节小端块号(共9字节) */
    void get_leaf_prefix(size_t id, u8_t *out);
    /* get_prefix_len:返回叶前缀长度(固定9字节) */
    size_t get_prefix_len(){return 9;};
    /* get_root_prefix:生成根HMAC的域分离前缀 "R"+8字节小端块数+各线程IV。
       返回内部缓冲(非线程安全,仅供根合并单线程阶段调用)。 */
    u8_t* get_root_prefix(size_t total_blocks, u8_t * iv, u8_t n);
};

#endif
