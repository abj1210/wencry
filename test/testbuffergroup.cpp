#include "multi_buffergroup.h"
#include "testutil.h"
#include "gtest/gtest.h"

#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

static void write_file(const char *path, const u8_t *data, size_t n) {
  FILE *f = fopen(path, "wb");
  ASSERT_TRUE(f != NULL);
  if (n > 0)
    fwrite(data, 1, n, f);
  fclose(f);
}

static std::vector<u8_t> read_file(const char *path) {
  FILE *f = fopen(path, "rb");
  EXPECT_TRUE(f != NULL);
  if (f == NULL)
    return std::vector<u8_t>();
  fseek(f, 0, SEEK_END);
  long sz = ftell(f);
  fseek(f, 0, SEEK_SET);
  std::vector<u8_t> v(sz > 0 ? (size_t)sz : 0);
  if (sz > 0)
    fread(v.data(), 1, (size_t)sz, f);
  fclose(f);
  return v;
}

/*
run_pipeline:用真实线程驱动完整流水线(读 -> 工作 -> 写),调用序列与
kernel/multi_pipeline/multicry.cpp 中的调度器一致。
注意:读线程会阻塞在 finishLoading 的背压上,因此三个阶段的驱动必须并发运行,
不能像旧版测试那样在单线程里顺序调用(会自锁)。
AES/HMAC 用空操作占位,只验证缓冲池状态机与 PKCS7 填充/截断逻辑。
*/
static void run_pipeline(pipe_mode mode, u32_t threads, const char *inpath, const char *outpath) {
  BufferGroup *bg = BufferGroup::getInstance();
  bg->setBufferGroup(threads, mode);

  FILE *fin = fopen(inpath, "rb");
  ASSERT_TRUE(fin != NULL);
  FILE *fout = NULL;
  if (mode != PIPE_VERIFY) {
    fout = fopen(outpath, "wb+");
    ASSERT_TRUE(fout != NULL);
  }
  const bool ispadding = (mode == PIPE_ENCRYPT);

  // 写线程
  std::thread writer([&] {
    u64_t next = 0;
    while (true) {
      IoBuffer *buf = bg->recvProcessedPool(next);
      if (bg->stopWorker(buf))
        break;                       // NULL 哨兵:所有块都已写出
      if (mode != PIPE_VERIFY)
        buf->exportBuffer(fout, bg->getFinalBlock(next), ispadding);
      bg->sendIdlePool(buf);
      next++;
    }
  });

  // 工作线程(按 seq%threads 路由,只领取自己名下的块)
  std::vector<std::thread> workers;
  for (u32_t i = 0; i < threads; ++i)
    workers.emplace_back([&bg, mode, i] {
      u64_t next = i;
      while (true) {
        IoBuffer *buf = bg->recvWorkPool(next);
        if (bg->stopWorker(buf))
          break;                     // NULL 哨兵:本线程已无任务
        for (u8_t *p = buf->getEntry(); p != NULL; p = buf->getEntry()) {
          // 真实实现此处执行 AES/HMAC
        }
        next = bg->sendProcessedPool(buf);
      }
    });

  // 读线程(当前线程)
  u64_t next = 0;
  while (true) {
    IoBuffer *buf = bg->recvIdlePool(next);
    loadstate_t ls = buf->loadBuffer(fin, ispadding);
    if (bg->finishLoading(buf, ls, next))
      break;                         // FINAL/NODATA:已读到末尾
    ++next;
  }

  writer.join();
  for (size_t i = 0; i < workers.size(); ++i)
    workers[i].join();

  fclose(fin);
  if (fout != NULL)
    fclose(fout);
  BufferGroup::delInstance();
}

TEST(IOBuffer, encrypt_padding) {
  char in[64], out[64];
  make_tmp_name(in, sizeof(in), "ib_in");
  make_tmp_name(out, sizeof(out), "ib_out");
  u8_t data[16] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                   'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p'};
  write_file(in, data, 16);

  FILE *fin = fopen(in, "rb");
  FILE *fout = fopen(out, "wb+");
  ASSERT_TRUE(fin != NULL);
  ASSERT_TRUE(fout != NULL);
  IoBuffer *b = new IoBuffer;
  EXPECT_EQ(FINAL, b->loadBuffer(fin, true));
  EXPECT_EQ(32u, b->dataLen());

  u8_t *e0 = b->getEntry();
  ASSERT_TRUE(e0 != NULL);
  EXPECT_EQ(0, memcmp(e0, data, 16));
  u8_t *e1 = b->getEntry();
  ASSERT_TRUE(e1 != NULL);
  for (int i = 0; i < 16; ++i)
    EXPECT_EQ(0x10, (int)e1[i]);
  EXPECT_TRUE(b->getEntry() == NULL);
  EXPECT_EQ(32u, b->exportBuffer(fout, true, true));
  delete b;
  fclose(fin);
  fclose(fout);

  std::vector<u8_t> got = read_file(out);
  ASSERT_EQ(32u, got.size());
  EXPECT_EQ(0, memcmp(got.data(), data, 16));
  for (int i = 16; i < 32; ++i)
    EXPECT_EQ(0x10, (int)got[i]);
  remove(in);
  remove(out);
}

TEST(IOBuffer, decrypt_unpadding) {
  char in[64], out[64];
  make_tmp_name(in, sizeof(in), "ib_in");
  make_tmp_name(out, sizeof(out), "ib_out");
  u8_t data[16] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                   'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p'};
  u8_t file[32];
  memcpy(file, data, 16);
  for (int i = 16; i < 32; ++i)
    file[i] = 0x10;
  write_file(in, file, 32);

  FILE *fin = fopen(in, "rb");
  FILE *fout = fopen(out, "wb+");
  ASSERT_TRUE(fin != NULL);
  ASSERT_TRUE(fout != NULL);
  IoBuffer *b = new IoBuffer;
  EXPECT_EQ(FINAL, b->loadBuffer(fin, false));
  EXPECT_EQ(32u, b->dataLen());
  ASSERT_TRUE(b->getEntry() != NULL);
  ASSERT_TRUE(b->getEntry() != NULL);
  EXPECT_TRUE(b->getEntry() == NULL);
  EXPECT_EQ(16u, b->exportBuffer(fout, true, false));
  delete b;
  fclose(fin);
  fclose(fout);

  std::vector<u8_t> got = read_file(out);
  ASSERT_EQ(16u, got.size());
  EXPECT_EQ(0, memcmp(got.data(), data, 16));
  remove(in);
  remove(out);
}

TEST(IOBuffer, empty_input_nodata) {
  char in[64];
  make_tmp_name(in, sizeof(in), "ib_empty");
  write_file(in, NULL, 0);
  FILE *fin = fopen(in, "rb");
  ASSERT_TRUE(fin != NULL);
  IoBuffer *b = new IoBuffer;
  EXPECT_EQ(NODATA, b->loadBuffer(fin, false));
  EXPECT_EQ(0u, b->dataLen());
  delete b;
  fclose(fin);
  remove(in);
}

TEST(IOBuffer, empty_input_padding_final) {
  char in[64];
  make_tmp_name(in, sizeof(in), "ib_empty_pad");
  write_file(in, NULL, 0);
  FILE *fin = fopen(in, "rb");
  ASSERT_TRUE(fin != NULL);
  IoBuffer *b = new IoBuffer;
  // 加密空文件:PKCS7 规定必须产生一个全 0x10 的填充块
  EXPECT_EQ(FINAL, b->loadBuffer(fin, true));
  EXPECT_EQ(16u, b->dataLen());
  u8_t *e0 = b->getEntry();
  ASSERT_TRUE(e0 != NULL);
  for (int i = 0; i < 16; ++i)
    EXPECT_EQ(0x10, (int)e0[i]);
  EXPECT_TRUE(b->getEntry() == NULL);
  delete b;
  fclose(fin);
  remove(in);
}

TEST(BufferGroup, singleton_lifecycle) {
  BufferGroup *a = BufferGroup::getInstance();
  ASSERT_TRUE(a != NULL);
  EXPECT_EQ(a, BufferGroup::getInstance());
  BufferGroup::delInstance();
  BufferGroup *b = BufferGroup::getInstance();
  ASSERT_TRUE(b != NULL);
  BufferGroup::delInstance();
}

TEST(BufferGroup, pipeline_padding_roundtrip) {
  char in[64], enc[64], dec[64];
  make_tmp_name(in, sizeof(in), "bg_in");
  make_tmp_name(enc, sizeof(enc), "bg_enc");
  make_tmp_name(dec, sizeof(dec), "bg_dec");

  u8_t data[20];
  for (int i = 0; i < 20; ++i)
    data[i] = (u8_t)('A' + (i % 26));
  write_file(in, data, 20);

  run_pipeline(PIPE_ENCRYPT, 1, in, enc);
  std::vector<u8_t> encrypted = read_file(enc);
  ASSERT_EQ(32u, encrypted.size());
  EXPECT_EQ(0, memcmp(encrypted.data(), data, 20));
  for (int i = 20; i < 32; ++i)
    EXPECT_EQ(12, (int)encrypted[i]);

  run_pipeline(PIPE_DECRYPT, 1, enc, dec);
  std::vector<u8_t> decrypted = read_file(dec);
  ASSERT_EQ(20u, decrypted.size());
  EXPECT_EQ(0, memcmp(decrypted.data(), data, 20));

  remove(in);
  remove(enc);
  remove(dec);
}

/*
单块数据 + 多工作线程:块数少于线程数,序号大于末尾的工作线程必须靠 NULL 哨兵
正常退出(旧实现会在这里永久挂起)。
*/
TEST(BufferGroup, pipeline_small_multithread) {
  char in[64], enc[64], dec[64];
  make_tmp_name(in, sizeof(in), "bg_mt_in");
  make_tmp_name(enc, sizeof(enc), "bg_mt_enc");
  make_tmp_name(dec, sizeof(dec), "bg_mt_dec");

  u8_t data[20];
  for (int i = 0; i < 20; ++i)
    data[i] = (u8_t)(i * 7 + 1);
  write_file(in, data, 20);

  run_pipeline(PIPE_ENCRYPT, 4, in, enc);
  run_pipeline(PIPE_DECRYPT, 4, enc, dec);
  std::vector<u8_t> decrypted = read_file(dec);
  ASSERT_EQ(20u, decrypted.size());
  EXPECT_EQ(0, memcmp(decrypted.data(), data, 20));

  remove(in);
  remove(enc);
  remove(dec);
}

TEST(BufferGroup, pipeline_empty_file) {
  char in[64], enc[64], dec[64];
  make_tmp_name(in, sizeof(in), "bg_empty_in");
  write_file(in, NULL, 0);

  // 加密空文件:输出恰好一个 PKCS7 填充块
  make_tmp_name(enc, sizeof(enc), "bg_empty_enc");
  run_pipeline(PIPE_ENCRYPT, 2, in, enc);
  std::vector<u8_t> encrypted = read_file(enc);
  ASSERT_EQ(16u, encrypted.size());
  for (int i = 0; i < 16; ++i)
    EXPECT_EQ(0x10, (int)encrypted[i]);

  // 解密回来应为空文件(整块都是填充,截断为 0 字节)
  make_tmp_name(dec, sizeof(dec), "bg_empty_dec");
  run_pipeline(PIPE_DECRYPT, 2, enc, dec);
  EXPECT_EQ(0u, read_file(dec).size());

  remove(in);
  remove(enc);
  remove(dec);
}

TEST(BufferGroup, pipeline_verify_only) {
  char in[64], out[64];
  make_tmp_name(in, sizeof(in), "bg_verify_in");
  make_tmp_name(out, sizeof(out), "bg_verify_out");
  u8_t file[32];
  for (int i = 0; i < 32; ++i)
    file[i] = (u8_t)i;
  write_file(in, file, 32);

  // 验证模式不写文件,但流水线必须正常收尾(不得挂起)
  run_pipeline(PIPE_VERIFY, 3, in, out);
  EXPECT_TRUE(fopen(out, "rb") == NULL);

  remove(in);
}

/*
多块流水线(块大小 16MB):数据为 16MB+16 字节,产生一个 FULL 块和一个 FINAL 块,
覆盖 next 递增、跨线程路由与末块填充/截断。
*/
TEST(BufferGroup, pipeline_multi_chunk_roundtrip) {
  const size_t data_size = (size_t)IoBuffer::sum + 16;
  std::vector<u8_t> data(data_size);
  for (size_t i = 0; i < data_size; ++i)
    data[i] = (u8_t)(i * 31 + 5);

  char in[64], enc[64], dec[64];
  make_tmp_name(in, sizeof(in), "bg_big_in");
  make_tmp_name(enc, sizeof(enc), "bg_big_enc");
  make_tmp_name(dec, sizeof(dec), "bg_big_dec");
  write_file(in, data.data(), data.size());

  run_pipeline(PIPE_ENCRYPT, 4, in, enc);
  std::vector<u8_t> encrypted = read_file(enc);
  ASSERT_EQ(data_size + 16, encrypted.size());   // 末块补一个 0x10 填充块
  EXPECT_EQ(0, memcmp(encrypted.data(), data.data(), data_size));
  for (int i = 0; i < 16; ++i)
    EXPECT_EQ(0x10, (int)encrypted[data_size + (size_t)i]);

  run_pipeline(PIPE_DECRYPT, 4, enc, dec);
  std::vector<u8_t> decrypted = read_file(dec);
  ASSERT_EQ(data_size, decrypted.size());
  EXPECT_EQ(0, memcmp(decrypted.data(), data.data(), data_size));

  remove(in);
  remove(enc);
  remove(dec);
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
