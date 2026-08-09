#include "cry.h"
#include "getval.h"
#include "base64.h"
#include "test.h"
#include "testutil.h"
#include "gtest/gtest.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <chrono>

/*################################
  辅助函数
################################*/

static int g_tfid = 0;
static const u8_t TKEY[16] = {'t', 'e', 's', 't', '-', 'k', 'e', 'y',
                              '0', '1', '2', '3', '4', '5', '6', '7'};

/* CLI 完整往返: -e --cmode/--hmode -> -d -> cmp */
static int cli_roundtrip(size_t size, u8_t ctype, u8_t htype) {
  char fname[128], wenc[128], out[128], ct[16], ht[16];
  int id = ++g_tfid;
  snprintf(fname, sizeof fname, "tb_%d.bin", id);
  snprintf(wenc, sizeof wenc, "tb_%d.bin.wenc", id);
  snprintf(out, sizeof out, "tb_out_%d.bin", id);
  write_pattern_file(fname, size);
  snprintf(ct, sizeof ct, "%d", ctype);
  snprintf(ht, sizeof ht, "%d", htype);
  char *name = (char *)"./wencry";
  const char *argv1[] = {name, "-e", "-i", fname, "-o", wenc, "--cmode", ct,
                         "--hmode", ht, "-k", "ABEiM0RVZneImaq7zN3u/w==",
                         "-n"};
  if (!exec(13, (char **)argv1)) {
    remove(fname);
    return 0;
  }
  const char *argv2[] = {name, "-d", "-i", wenc, "-o", out, "-k",
                         "ABEiM0RVZneImaq7zN3u/w==", "-n"};
  if (!exec(9, (char **)argv2)) {
    remove(fname);
    remove(wenc);
    return 0;
  }
  FILE *f1 = fopen(fname, "rb"), *f2 = fopen(out, "rb");
  int r = (f1 && f2) ? cmp_file(f1, f2) : 0;
  remove(fname);
  remove(wenc);
  remove(out);
  return r;
}

/* 直接构造 runcrypt, 指定线程数往返 */
static int thread_roundtrip(size_t size, u8_t threads, u8_t ctype,
                            u8_t htype) {
  char fname[128], wenc[128], out[128];
  int id = ++g_tfid;
  snprintf(fname, sizeof fname, "tb_%d.bin", id);
  snprintf(wenc, sizeof wenc, "tb_%d.bin.wenc", id);
  snprintf(out, sizeof out, "tb_out_%d.bin", id);
  write_pattern_file(fname, size);

  u8_t r_buf[256];
  for (int i = 0; i < 256; ++i)
    r_buf[i] = (u8_t)(i * 13);
  Settings s(ctype, htype, true);

  FILE *fin = fopen(fname, "rb"), *fout = fopen(wenc, "wb+");
  if (!fin || !fout) {
    remove(fname);
    return 0;
  }
  runcrypt r1(fin, fout, (u8_t *)TKEY, s, threads);
  bool ok1 = r1.execute_encrypt(size, r_buf);

  FILE *fin2 = fopen(wenc, "rb"), *fout2 = fopen(out, "wb+");
  if (!fin2 || !fout2) {
    remove(fname);
    remove(wenc);
    return 0;
  }
  runcrypt r2(fin2, fout2, (u8_t *)TKEY, s, threads);
  bool ok2 = r2.execute_decrypt(size);

  FILE *f1 = fopen(fname, "rb"), *f2 = fopen(out, "rb");
  int r = (ok1 && ok2 && f1 && f2) ? cmp_file(f1, f2) : 0;
  remove(fname);
  remove(wenc);
  remove(out);
  return r;
}

/*################################
  边界尺寸往返
################################*/

TEST(Testboundary, size_boundaries_cbc) {
  static const size_t sizes[] = {
      0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 0x10000,
      0x1000000 - 1, 0x1000000, 0x1000000 + 1, 0x2000000, 0x3000000};
  for (size_t s : sizes)
    EXPECT_EQ(1, cli_roundtrip(s, 1, 0)) << "cbc size=" << s;
}

TEST(Testboundary, size_boundaries_ctr) {
  static const size_t sizes[] = {0, 1, 15, 16, 17, 63, 64, 65, 127, 128,
                                 129, 0x10000, 0x1000000};
  for (size_t s : sizes)
    EXPECT_EQ(1, cli_roundtrip(s, 2, 0)) << "ctr size=" << s;
}

TEST(Testboundary, size_boundaries_hash) {
  static const size_t sizes[] = {0, 1, 64, 100000};
  for (size_t s : sizes) {
    EXPECT_EQ(1, cli_roundtrip(s, 1, 1)) << "md5 size=" << s;
    EXPECT_EQ(1, cli_roundtrip(s, 1, 2)) << "sha256 size=" << s;
  }
}

/*################################
  线程数变化往返
################################*/

TEST(Testboundary, thread_count_roundtrip) {
  static const u8_t ts[] = {1, 2, 8, 16};
  for (u8_t t : ts)
    EXPECT_EQ(1, thread_roundtrip(1 << 20, t, 1, 0))
        << "threads=" << (int)t;
  EXPECT_EQ(1, thread_roundtrip(0x1000000, 1, 1, 0)) << "1-thread exact16MB";
}

/* 指定线程数加密, 再用CLI(默认4线程)解密, 验证文件头自描述线程数 */
static int thread_encrypt_then_cli_decrypt(size_t size, u8_t threads) {
  char fname[128], wenc[160], out[160];
  int id = ++g_tfid;
  snprintf(fname, sizeof fname, "tb_%d.bin", id);
  snprintf(wenc, sizeof wenc, "%s.wenc", fname);
  snprintf(out, sizeof out, "tb_out_%d.bin", id);
  write_pattern_file(fname, size);
  u8_t r_buf[256];
  for (int i = 0; i < 256; ++i)
    r_buf[i] = (u8_t)(i * 13);
  u8_t key[16];
  base64_to_hex((const u8_t *)"ABEiM0RVZneImaq7zN3u/w==", 24, key);
  Settings s(1, 0, true);
  FILE *fin = fopen(fname, "rb"), *fout = fopen(wenc, "wb+");
  if (!fin || !fout) {
    remove(fname);
    return 0;
  }
  runcrypt r1(fin, fout, key, s, threads);
  bool ok1 = r1.execute_encrypt(size, r_buf);
  if (!ok1) {
    remove(fname);
    remove(wenc);
    return 0;
  }
  const char *name = "./wencry";
  const char *a[] = {name, "-d", "-i", wenc, "-o", out, "-k",
                     "ABEiM0RVZneImaq7zN3u/w==", "-n"};
  bool ok2 = exec(9, (char **)a);
  if (!ok2) {
    remove(fname);
    remove(wenc);
    return 0;
  }
  FILE *f1 = fopen(fname, "rb"), *f2 = fopen(out, "rb");
  int r = (f1 && f2) ? cmp_file(f1, f2) : 0;
  remove(fname);
  remove(wenc);
  remove(out);
  return r;
}

TEST(Testboundary, cross_thread_format) {
  EXPECT_EQ(1, thread_encrypt_then_cli_decrypt(100000, 2)) << "2-thread enc";
  EXPECT_EQ(1, thread_encrypt_then_cli_decrypt(0x100000, 3)) << "3-thread enc";
}

/*################################
  文件头布局
################################*/

TEST(Testboundary, file_header_layout) {
  ASSERT_EQ(1, cli_roundtrip(100, 1, 0)) << "sanity encrypt";
  // 重新加密一个已知 ctype/htype 的文件以检查头字节
  {
    char fname[64], wenc[80], ct[8], ht[8];
    snprintf(fname, sizeof fname, "tb_hdr_%d.bin", ++g_tfid);
    snprintf(wenc, sizeof wenc, "%s.wenc", fname);
    write_pattern_file(fname, 128);
    snprintf(ct, sizeof ct, "%d", 3);
    snprintf(ht, sizeof ht, "%d", 2);
    char *name = (char *)"./wencry";
    const char *argv1[] = {name, "-e", "-i", fname, "-o", wenc, "--cmode", ct,
                           "--hmode", ht, "-k", "ABEiM0RVZneImaq7zN3u/w==",
                           "-n"};
    ASSERT_TRUE(exec(13, (char **)argv1));
    FILE *fp = fopen(wenc, "rb");
    ASSERT_TRUE(fp != NULL);
    u8_t hdr[160];
    ASSERT_EQ(160u, fread(hdr, 1, 160, fp));
    fclose(fp);
    u64_t mn;
    memcpy(&mn, hdr, 8);
    EXPECT_EQ(0xA5C3A5C3A5C3A5C3ull, mn) << "magic number";
    EXPECT_EQ(3, (int)hdr[8]) << "ctype byte";
    EXPECT_EQ(2, (int)hdr[9]) << "htype byte";
    EXPECT_EQ(4, (int)hdr[47]) << "threads byte";
    // HMAC 区域(10..)应非全零
    bool hmac_nonzero = false;
    for (int i = 10; i < 10 + 32; ++i)
      if (hdr[i] != 0) hmac_nonzero = true;
    EXPECT_TRUE(hmac_nonzero) << "HMAC region non-zero";
    // IV 区域(48..48+80)应非全零
    bool iv_nonzero = false;
    for (int i = 48; i < 128; ++i)
      if (hdr[i] != 0) iv_nonzero = true;
    EXPECT_TRUE(iv_nonzero) << "IV region non-zero";
    remove(fname);
    remove(wenc);
  }
}

/*################################
  失败路径 (execute_verify)
################################*/

static bool encrypt_small(const char *fname, const char *wenc, u8_t ctype,
                          u8_t htype) {
  FILE *fp = fopen(fname, "wb");
  if (!fp) return false;
  const char *msg = "hello boundary test 0123456789";
  fwrite(msg, 1, strlen(msg), fp);
  fclose(fp);
  u8_t r_buf[256];
  for (int i = 0; i < 256; ++i)
    r_buf[i] = (u8_t)(i * 7);
  FILE *fin = fopen(fname, "rb"), *fout = fopen(wenc, "wb+");
  if (!fin || !fout) return false;
  Settings s(ctype, htype, true);
  runcrypt r(fin, fout, (u8_t *)TKEY, s, 4);
  bool ok = r.execute_encrypt(strlen(msg), r_buf);
  return ok;
}

static bool verify_file(const char *wenc) {
  FILE *fp = fopen(wenc, "rb");
  if (!fp) return false;
  Settings s(0, 0, true);
  runcrypt r(fp, NULL, (u8_t *)TKEY, s, 4);
  bool ok = r.execute_verify(0);
  return ok;
}

TEST(Testboundary, verify_valid) {
  ASSERT_TRUE(encrypt_small("tb_ok.txt", "tb_ok.wenc", 1, 0));
  EXPECT_TRUE(verify_file("tb_ok.wenc"));
  remove("tb_ok.txt");
  remove("tb_ok.wenc");
}

TEST(Testboundary, verify_bad_magic) {
  ASSERT_TRUE(encrypt_small("tb_bm.txt", "tb_bm.wenc", 1, 0));
  FILE *fp = fopen("tb_bm.wenc", "rb+");
  ASSERT_TRUE(fp != NULL);
  u8_t z = 0;
  fwrite(&z, 1, 1, fp);
  fclose(fp);
  EXPECT_FALSE(verify_file("tb_bm.wenc"));
  remove("tb_bm.txt");
  remove("tb_bm.wenc");
}

TEST(Testboundary, verify_corrupt_data) {
  ASSERT_TRUE(encrypt_small("tb_cd.txt", "tb_cd.wenc", 1, 0));
  FILE *fp = fopen("tb_cd.wenc", "rb+");
  ASSERT_TRUE(fp != NULL);
  fseek(fp, FILE_TEXT_MARK(4) + 5, SEEK_SET);
  u8_t c;
  fread(&c, 1, 1, fp);
  fseek(fp, -1, SEEK_CUR);
  c ^= 0xff;
  fwrite(&c, 1, 1, fp);
  fclose(fp);
  EXPECT_FALSE(verify_file("tb_cd.wenc"));
  remove("tb_cd.txt");
  remove("tb_cd.wenc");
}

TEST(Testboundary, verify_truncated) {
  ASSERT_TRUE(encrypt_small("tb_tr.txt", "tb_tr.wenc", 1, 0));
  FILE *in = fopen("tb_tr.wenc", "rb");
  ASSERT_TRUE(in != NULL);
  fseek(in, 0, SEEK_END);
  long sz = ftell(in);
  fseek(in, 0, SEEK_SET);
  FILE *out = fopen("tb_tr.short", "wb");
  ASSERT_TRUE(out != NULL);
  u8_t buf[512];
  size_t left = (size_t)(sz / 2);
  while (left) {
    size_t n = left < sizeof(buf) ? left : sizeof(buf);
    fread(buf, 1, n, in);
    fwrite(buf, 1, n, out);
    left -= n;
  }
  fclose(in);
  fclose(out);
  EXPECT_FALSE(verify_file("tb_tr.short"));
  remove("tb_tr.txt");
  remove("tb_tr.wenc");
  remove("tb_tr.short");
}

TEST(Testboundary, verify_too_short) {
  FILE *fp = fopen("tb_ts.wenc", "wb");
  ASSERT_TRUE(fp != NULL);
  u8_t z[10] = {0};
  fwrite(z, 1, 10, fp);
  fclose(fp);
  EXPECT_FALSE(verify_file("tb_ts.wenc"));
  remove("tb_ts.wenc");
}

/*################################
  CLI 参数错误路径
################################*/

TEST(Testboundary, cli_invalid_args) {
  char fname[64];
  snprintf(fname, sizeof fname, "tb_cli_%d.bin", ++g_tfid);
  write_pattern_file(fname, 64);
  const char *name = "./wencry";

  {
    const char *a[] = {name, "-e", "-i", fname, "-k", "invalid!!"};
    EXPECT_FALSE(exec(6, (char **)a)) << "invalid base64 key";
  }
  {
    const char *a[] = {name, "-e", "-i", fname, "--cmode", "9"};
    EXPECT_FALSE(exec(6, (char **)a)) << "invalid cmode";
  }
  {
    const char *a[] = {name, "-e", "-d", "-i", fname};
    EXPECT_FALSE(exec(5, (char **)a)) << "double mode";
  }
  {
    const char *a[] = {name, "-e", "-i", "no_such_file_xyz.bin"};
    EXPECT_FALSE(exec(4, (char **)a)) << "missing file";
  }
  {
    const char *a[] = {name, "-i", fname};
    EXPECT_FALSE(exec(3, (char **)a)) << "no mode";
  }
  {
    const char *a[] = {name, "-V"};
    EXPECT_TRUE(exec(2, (char **)a)) << "version flag";
  }
  {
    const char *a[] = {name, "-h"};
    EXPECT_TRUE(exec(2, (char **)a)) << "help flag";
  }
  remove(fname);
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
