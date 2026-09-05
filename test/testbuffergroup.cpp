#include "multi_buffergroup.h"
#include "testutil.h"
#include "gtest/gtest.h"

#include <cstdio>
#include <cstring>
#include <vector>

static void write_file(const char *path, const u8_t *data, size_t n) {
  FILE *f = fopen(path, "wb");
  ASSERT_TRUE(f != NULL);
  fwrite(data, 1, n, f);
  fclose(f);
}

static std::vector<u8_t> read_file(const char *path) {
  FILE *f = fopen(path, "rb");
  EXPECT_TRUE(f != NULL);
  fseek(f, 0, SEEK_END);
  long sz = ftell(f);
  fseek(f, 0, SEEK_SET);
  std::vector<u8_t> v(sz > 0 ? (size_t)sz : 0);
  if (sz > 0)
    fread(v.data(), 1, (size_t)sz, f);
  fclose(f);
  return v;
}

/* 单线程驱动完整流水线(读 -> 工作 -> 写),验证缓冲池状态机与 padding 逻辑。 */
static void run_pipeline(pipe_mode mode, const char *inpath, const char *outpath) {
  BufferGroup *bg = BufferGroup::getInstance();
  bg->setBufferGroup(1, mode);

  FILE *fin = fopen(inpath, "rb");
  FILE *fout = fopen(outpath, "wb+");
  ASSERT_TRUE(fin != NULL);
  ASSERT_TRUE(fout != NULL);
  const bool ispadding = (mode == PIPE_ENCRYPT);

  // 读线程
  u64_t next = 0;
  while (true) {
    IoBuffer *buf = bg->waitClearedBuffer();
    if (buf == NULL)
      break;
    loadstate_t ls = buf->loadBuffer(fin, ispadding);
    if (bg->finishLoading(buf, ls, next++))
      break;
  }

  // 工作线程(单线程,id=0)
  u64_t wnext = 0;
  while (true) {
    IoBuffer *buf = bg->waitLoadedBuffer(0, wnext);
    if (bg->stopWorker(buf))
      break;
    for (u8_t *p = buf->getEntry(); p != NULL; p = buf->getEntry()) {
      // 占位:真实实现此处执行 AES/HMAC
    }
    wnext = bg->finishProcessing(buf);
  }

  // 写线程
  u64_t cnext = 0;
  while (true) {
    IoBuffer *buf = bg->waitProcessedBuffer(cnext);
    if (bg->stopWorker(buf))
      break;
    if (mode != PIPE_VERIFY)
      buf->exportBuffer(fout, ispadding);
    bg->finishClearing(buf);
    cnext++;
  }

  fclose(fin);
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
  EXPECT_EQ(32u, b->exportBuffer(fout, true));
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
  EXPECT_EQ(16u, b->exportBuffer(fout, false));
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

  run_pipeline(PIPE_ENCRYPT, in, enc);
  std::vector<u8_t> encrypted = read_file(enc);
  ASSERT_EQ(32u, encrypted.size());
  EXPECT_EQ(0, memcmp(encrypted.data(), data, 20));
  for (int i = 20; i < 32; ++i)
    EXPECT_EQ(12, (int)encrypted[i]);

  run_pipeline(PIPE_DECRYPT, enc, dec);
  std::vector<u8_t> decrypted = read_file(dec);
  ASSERT_EQ(20u, decrypted.size());
  EXPECT_EQ(0, memcmp(decrypted.data(), data, 20));

  remove(in);
  remove(enc);
  remove(dec);
}

TEST(BufferGroup, pipeline_empty_nodata) {
  char in[64], out[64];
  make_tmp_name(in, sizeof(in), "bg_empty_in");
  make_tmp_name(out, sizeof(out), "bg_empty_out");
  write_file(in, NULL, 0);

  run_pipeline(PIPE_DECRYPT, in, out);
  std::vector<u8_t> decrypted = read_file(out);
  EXPECT_EQ(0u, decrypted.size());

  remove(in);
  remove(out);
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
