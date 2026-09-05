#include "merkletree.h"
#include "fheader.h"
#include "testutil.h"
#include "gtest/gtest.h"

#include <cstring>
#include <vector>

/* 测试密钥(16 字节,与 HMAC 测试一致) */
static const u8_t key[16] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                             '0', '1', '2', '3', '4', '5', '6', '7'};

/*
leaf_hmac:为第 blk_id 块计算叶子摘要
域分离: prefix = "L" + 8 字节小端 blk_id,再喂入确定性的块数据。
*/
static std::vector<u8_t> leaf_hmac(u8_t hashtype, size_t blk_id)
{
  Hmac h;
  u8_t prefix[1 + 8];
  prefix[0] = 'L';
  for (int i = 0; i < 8; ++i)
    prefix[1 + i] = (u8_t)((blk_id >> (8 * i)) & 0xff);

  u8_t data[64];
  for (int i = 0; i < 64; ++i)
    data[i] = (u8_t)(blk_id * 31u + (size_t)i);

  HashFactory hf;
  HashMaster *probe = hf.getHasher(HashFactory::getType(hashtype));
  size_t hs = probe->getHashLength();
  delete probe;

  std::vector<u8_t> out(hs);
  h.getHmac(hashtype, (u8_t *)key, data, out.data(), sizeof(data), prefix, sizeof(prefix));
  return out;
}

/*
reference_root:独立、直白的自底向上二叉 Merkle 树参考实现。
相邻节点两两合并(左边在前),落单节点上提;内部节点 = H('N' || left || right)。
该参考在叶子数为 1,2,3,4,5,6,8 时与 MerkleTreeMaster 的规范树形一致。
*/
static std::vector<u8_t> reference_root(u8_t hashtype,
                                        const std::vector<std::vector<u8_t>> &leaves)
{
  HashFactory hf;
  HashMaster *hm = hf.getHasher(HashFactory::getType(hashtype));
  size_t hs = hm->getHashLength();

  std::vector<std::vector<u8_t>> level = leaves;
  while (level.size() > 1)
  {
    std::vector<std::vector<u8_t>> next;
    for (size_t i = 0; i < level.size(); i += 2)
    {
      if (i + 1 < level.size())
      {
        std::vector<u8_t> buf(1 + 2 * hs);
        buf[0] = 'N';
        std::memcpy(&buf[1], level[i].data(), hs);
        std::memcpy(&buf[1 + hs], level[i + 1].data(), hs);
        std::vector<u8_t> out(hs);
        hm->getStringHash(buf.data(), (u32_t)buf.size(), out.data());
        next.push_back(std::move(out));
      }
      else
      {
        next.push_back(level[i]);
      }
    }
    level = std::move(next);
  }
  delete hm;
  return level[0];
}

/* 对指定哈希类型与块数执行:参考值对比 + 插入顺序无关性 + 块数校验 */
static void run_case(u8_t hashtype, size_t nblocks)
{
  std::vector<std::vector<u8_t>> leaves(nblocks);
  for (size_t i = 0; i < nblocks; ++i)
    leaves[i] = leaf_hmac(hashtype, i);

  std::vector<u8_t> ref = reference_root(hashtype, leaves);
  size_t hs = ref.size();

  // 顺序插入
  {
    MerkleTreeMaster mt;
    mt.setHashType(hashtype);
    for (size_t i = 0; i < nblocks; ++i)
      mt.addBlockHmac(i, leaves[i].data());
    std::vector<u8_t> top(hs);
    size_t cnt = mt.getTopHash(top.data());
    EXPECT_EQ(cnt, nblocks);
    EXPECT_EQ(top, ref);
  }

  // 逆序插入(验证 sync_queue 的乱序处理)
  {
    MerkleTreeMaster mt;
    mt.setHashType(hashtype);
    for (size_t i = nblocks; i-- > 0;)
      mt.addBlockHmac(i, leaves[i].data());
    std::vector<u8_t> top(hs);
    size_t cnt = mt.getTopHash(top.data());
    EXPECT_EQ(cnt, nblocks);
    EXPECT_EQ(top, ref);
  }
}

TEST(MerkleTreeMaster, sha1) {
  for (size_t n : {1u, 2u, 3u, 4u, 5u, 6u, 8u})
    run_case(HT_SHA1, n);
}

TEST(MerkleTreeMaster, md5) {
  for (size_t n : {1u, 2u, 3u, 4u, 5u, 6u, 8u})
    run_case(HT_MD5, n);
}

TEST(MerkleTreeMaster, sha256) {
  for (size_t n : {1u, 2u, 3u, 4u, 5u, 6u, 8u})
    run_case(HT_SHA256, n);
}

/* getLeafPrefix:校验叶子域分离前缀的字节布局 "L"+8字节小端块号 */
TEST(MerkleTreeMaster, LeafPrefixLayout) {
  MerkleTreeMaster mt;
  mt.setHashType(HT_SHA256);
  EXPECT_EQ(mt.getPrefixLen(), 9u);

  u8_t out[9];
  mt.getLeafPrefix(0x12345678, out);
  EXPECT_EQ(out[0], 'L');
  EXPECT_EQ(out[1], 0x78);
  EXPECT_EQ(out[2], 0x56);
  EXPECT_EQ(out[3], 0x34);
  EXPECT_EQ(out[4], 0x12);
  for (int i = 5; i < 9; ++i)
    EXPECT_EQ(out[i], 0);
}

/* getRootPrefix:校验根前缀布局 "R"+8字节小端块数+各线程IV */
TEST(MerkleTreeMaster, RootPrefixLayout) {
  MerkleTreeMaster mt;
  mt.setHashType(HT_SHA1);

  u8_t iv[40];
  for (int i = 0; i < 40; ++i)
    iv[i] = (u8_t)(i + 1);

  u8_t *p = mt.getRootPrefix(0x01020304, iv, 2);
  ASSERT_NE(p, nullptr);
  EXPECT_EQ(p[0], 'R');
  EXPECT_EQ(p[1], 0x04);
  EXPECT_EQ(p[2], 0x03);
  EXPECT_EQ(p[3], 0x02);
  EXPECT_EQ(p[4], 0x01);
  for (int i = 5; i < 9; ++i)
    EXPECT_EQ(p[i], 0);
  EXPECT_EQ(std::memcmp(p + 9, iv, 40), 0);
}

/* setHashType/getHashSize:不同哈希类型返回正确摘要长度,重复设置不崩溃 */
TEST(MerkleTreeMaster, HashtypeAndHashSize) {
  MerkleTreeMaster mt;
  mt.setHashType(HT_SHA1);
  EXPECT_EQ(mt.getHashSize(), 20u);
  mt.setHashType(HT_MD5);
  EXPECT_EQ(mt.getHashSize(), 16u);
  mt.setHashType(HT_SHA256);
  EXPECT_EQ(mt.getHashSize(), 32u);
  mt.setHashType(HT_SHA1);
  EXPECT_EQ(mt.getHashSize(), 20u);
}

/* Hmac 一次性缓冲区重载:前缀改变结果、结果可复现、matchResult 显式缓冲区路径 */
TEST(Hmac, BufferGethmacPrefixAndMatch) {
  u8_t data[16];
  for (int i = 0; i < 16; ++i)
    data[i] = (u8_t)(0xa0 + i);

  u8_t prefix[9];
  for (int i = 0; i < 9; ++i)
    prefix[i] = (u8_t)('L' + i);

  u8_t no_prefix[32], with_prefix[32], with_prefix2[32];

  Hmac h;
  h.getHmac(HT_SHA256, (u8_t *)key, data, no_prefix, sizeof(data), NULL, 0);
  Hmac h2;
  h2.getHmac(HT_SHA256, (u8_t *)key, data, with_prefix, sizeof(data), prefix, sizeof(prefix));
  Hmac h3;
  h3.getHmac(HT_SHA256, (u8_t *)key, data, with_prefix2, sizeof(data), prefix, sizeof(prefix));

  EXPECT_NE(std::memcmp(no_prefix, with_prefix, 32), 0);
  EXPECT_EQ(std::memcmp(with_prefix, with_prefix2, 32), 0);

  // matchResult 的显式缓冲区参数版本
  EXPECT_TRUE(h3.matchResult(with_prefix, 32, with_prefix2));
  EXPECT_FALSE(h3.matchResult(no_prefix, 32, with_prefix2));
  EXPECT_FALSE(h3.matchResult(with_prefix, 20, with_prefix2));
}

/* FileHeader::writeHmac:写入输出文件指定偏移并读回校验 */
TEST(FileHeader, WriteHmac) {
  char fname[512];
  make_tmp_name(fname, sizeof(fname), "fh");

  u8_t Hmac[20];
  for (int i = 0; i < 20; ++i)
    Hmac[i] = (u8_t)(i * 3);

  {
    FILE *out = fopen(fname, "wb+");
    ASSERT_NE(out, nullptr);
    FileHeader fh(nullptr, out, (u8_t *)key, 4);
    fh.writeHmac(Hmac, sizeof(Hmac), 10); // 10 = FILE_HMAC_MARK
    fclose(out);
  }

  FILE *in = fopen(fname, "rb");
  ASSERT_NE(in, nullptr);
  u8_t readback[20] = {0};
  fseek(in, 10, SEEK_SET);
  size_t rd = fread(readback, 1, sizeof(readback), in);
  fclose(in);
  remove(fname);

  ASSERT_EQ(rd, 20u);
  EXPECT_EQ(std::memcmp(readback, Hmac, 20), 0);
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
