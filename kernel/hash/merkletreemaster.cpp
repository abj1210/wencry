#include "merkletree.h"
#include <cstring>

/*
MerkleTreeMaster 实现
叶子是调用方预计算的块 HMAC(经 add_block_hmac 传入),
内部节点按自底向上的二叉 Merkle 树两两合并:
  node = H('N' || left || right)
sync_queue(按 blk_head 的最小堆)负责接收乱序到达的块,
mtstack 按块号顺序合并,从而支持乱序添加。
*/

/*
judge_buddy:判断 left/right 是否能合并成规范的兄弟节点
left:左节点(低块号);right:右节点(高块号)
要求左右跨度相同,且右节点的末尾恰好落在合并后跨度对齐的边界上。
*/
bool MerkleTreeMaster::judge_buddy(MTNode& nodel, MTNode& noder){
    if((nodel.blk_tail-nodel.blk_head)!=(noder.blk_tail-noder.blk_head))
        return false;
    size_t total_size = noder.blk_tail - nodel.blk_head;
    if(total_size == 0)
        return false;
    return noder.blk_tail % total_size == 0;
}

/*
synchronize_stack:当堆顶块的块号正好续接栈尾时,把它搬入栈
return:本次是否有块成功搬入
*/
bool MerkleTreeMaster::synchronize_stack(){
    size_t stack_tail = mtstack.empty() ? 0 : mtstack.top().blk_tail;
    if(sync_queue.empty())
        return false;
    size_t queue_head = sync_queue.top().blk_head;
    if(stack_tail == queue_head){
        MTNode sync_node = sync_queue.top();
        sync_queue.pop();
        mtstack.push(sync_node);
        blk_cnt++;
        return true;
    }
    return false;
}

/*
hash_merge:在同步过程中持续合并栈顶可合并的兄弟节点
*/
void MerkleTreeMaster::hash_merge(){
    while(synchronize_stack()){
        while(mtstack.size()>1){
            MTNode noder = mtstack.top();  // 右(高块号)
            mtstack.pop();
            MTNode nodel = mtstack.top();  // 左(低块号)
            mtstack.pop();
            if(judge_buddy(nodel, noder)){
                MTNode merged_node(hash_size);
                merged_node.blk_head = nodel.blk_head;
                merged_node.blk_tail = noder.blk_tail;
                std::vector<u8_t> hash_buf(1 + hash_size*2);
                hash_buf[0] = 'N';
                memcpy(hash_buf.data()+1, nodel.hash_load.data(), hash_size);
                memcpy(hash_buf.data()+hash_size+1, noder.hash_load.data(), hash_size);
                hashmaster->getStringHash(hash_buf.data(), (u32_t)hash_buf.size(), merged_node.hash_load.data());
                mtstack.push(merged_node);
            }
            else{
                mtstack.push(nodel);
                mtstack.push(noder);
                break;
            }
        }
    }
}

/*
final_merge:把所有残留节点(无论是否为兄弟)自底向上合并到根
*/
void MerkleTreeMaster::final_merge(){
    while(mtstack.size()>1){
        MTNode noder = mtstack.top();
        mtstack.pop();
        MTNode nodel = mtstack.top();
        mtstack.pop();
        MTNode merged_node(hash_size);
        merged_node.blk_head = nodel.blk_head;
        merged_node.blk_tail = noder.blk_tail;
        std::vector<u8_t> hash_buf(1 + hash_size*2);
        hash_buf[0] = 'N';
        memcpy(hash_buf.data()+1, nodel.hash_load.data(), hash_size);
        memcpy(hash_buf.data()+hash_size+1, noder.hash_load.data(), hash_size);
        hashmaster->getStringHash(hash_buf.data(), (u32_t)hash_buf.size(), merged_node.hash_load.data());
        mtstack.push(merged_node);
    }
}

/*
check_mt:校验合并完成后树形合法(仅一个根、队列已空、覆盖 [0, blk_cnt))
*/
bool MerkleTreeMaster::check_mt(){
    if(mtstack.size()!=1)
        return false;
    if(!sync_queue.empty())
        return false;
    const MTNode& top = mtstack.top();
    if(top.blk_head!=0 || top.blk_tail!=blk_cnt)
        return false;
    return true;
}

/*
构造:按哈希类型创建哈希器,记录摘要长度
*/
MerkleTreeMaster::MerkleTreeMaster():
    hash_size(0), blk_cnt(0), hashmaster(NULL){}

/*
析构:释放哈希器
*/
MerkleTreeMaster::~MerkleTreeMaster(){
    delete hashmaster;
}

/*
set_hashtype:设置哈希类型并重置全部合并状态
hashtype:哈希类型(应在添加块前调用一次,重复调用会清空已合并节点)
*/
void MerkleTreeMaster::set_hashtype(u8_t hashtype){
    std::unique_lock<std::mutex> locker(mtx);
    delete hashmaster;
    hashmaster = NULL;
    HashFactory hf;
    hashmaster = hf.getHasher(HashFactory::getType(hashtype));
    hash_size = hashmaster->gethlen();
    blk_cnt = 0;
    while(!mtstack.empty())
        mtstack.pop();
    while(!sync_queue.empty())
        sync_queue.pop();
}

/*
add_block_hmac:添加一块已计算的叶子 HMAC(可按任意块号顺序调用)
blk_id:块号;blk_hmac:该块的 HMAC 摘要(长度 = hash_size)
*/
void MerkleTreeMaster::add_block_hmac(size_t blk_id, const u8_t *blk_hmac){
    std::unique_lock<std::mutex> locker(mtx);
    MTNode newnode(blk_id, hash_size);
    memcpy(newnode.hash_load.data(), blk_hmac, hash_size);
    sync_queue.push(newnode);
    hash_merge();
}

/*
get_top_hash:完成合并并输出根哈希
top_result:输出根摘要(长度 = hash_size)
return:成功返回块数;失败返回 (size_t)-1
*/
size_t MerkleTreeMaster::get_top_hash(u8_t * top_result){
    std::unique_lock<std::mutex> locker(mtx);
    final_merge();
    if(!check_mt())
        return (size_t)-1;
    memcpy(top_result, mtstack.top().hash_load.data(), hash_size);
    return blk_cnt;
}

/*
get_leaf_prefix:生成第 id 块叶子HMAC的域分离前缀
id:块号;out:输出缓冲(至少9字节)
布局:"L" + 8字节小端块号。
*/
void MerkleTreeMaster::get_leaf_prefix(size_t id, u8_t *out){
    memset(out, 0, 9);
    out[0]='L';
    for(int i=1;i<=8;i++){
        out[i] = id&0xff;
        id = id>>8;
    }
}

/*
get_root_prefix:生成根HMAC的域分离前缀
total_blocks:总块数;iv:各线程IV起始地址;n:线程数
布局:"R" + 8字节小端块数 + 20*n 字节IV。
返回内部缓冲 prefix,非线程安全,仅供根合并单线程阶段调用。
*/
u8_t* MerkleTreeMaster::get_root_prefix(size_t total_blocks, u8_t * iv, u8_t n){
    memset(prefix,0,sizeof(prefix));
    prefix[0]='R';
    for(int i=1;i<=8;i++){
        prefix[i] = total_blocks&0xff;
        total_blocks = total_blocks>>8;
    }
    memcpy(prefix+9,iv, 20 * n);
    return prefix;
}
