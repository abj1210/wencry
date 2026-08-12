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
  bool ok1 = true, ok2 = true;
  unsigned short dret = 0;
  runcrypt r1(fin, fout, (u8_t *)TKEY, s, threads);
  try{
    r1.execute_encrypt(size, r_buf);
  }
  catch(std::string errlog){
    std::cout<<errlog;
    ok1 = false;
  }
  FILE *fin2 = fopen(wenc, "rb"), *fout2 = fopen(out, "wb+");
  if (!fin2 || !fout2) {
    remove(fname);
    remove(wenc);
    return 0;
  }
  runcrypt r2(fin2, fout2, (u8_t *)TKEY, s, threads);
  try{
    dret = r2.execute_decrypt(size);
    if (dret != (unsigned short)((htype << 8) | ctype))
      ok2 = false;
  }
  catch(std::string errlog){
    std::cout<<errlog;
    ok2 = false;
  }
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
  try {
    r1.execute_encrypt(size, r_buf);
  } catch (const char *errlog) {
    std::cout << errlog << std::endl;
    remove(fname);
    remove(wenc);
    return 0;
  } catch (std::string errlog) {
    std::cout << errlog << std::endl;
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
  try {
    r.execute_encrypt(strlen(msg), r_buf);
    return true;
  } catch (const char *errlog) {
    std::cout << errlog << std::endl;
    return false;
  } catch (std::string errlog) {
    std::cout << errlog << std::endl;
    return false;
  }
}

/* 新版接口: execute_verify 成功返回空串, 失败抛异常并返回其消息 */
static std::string verify_file_key_str(const char *wenc, const u8_t *key) {
  FILE *fp = fopen(wenc, "rb");
  if (!fp) return "";
  Settings s(0, 0, true);
  runcrypt r(fp, NULL, (u8_t *)key, s, 4);
  try {
    r.execute_verify(0);
    return "";
  } catch (const char *errlog) {
    std::cout << errlog << std::endl;
    return errlog;
  } catch (std::string errlog) {
    std::cout << errlog << std::endl;
    return errlog;
  }
}

static std::string verify_file_str(const char *wenc) {
  return verify_file_key_str(wenc, TKEY);
}

static bool verify_file(const char *wenc) {
  return verify_file_str(wenc).empty();
}

/* 新版接口: execute_decrypt 成功返回空串并写出明文, 失败抛异常并返回其消息 */
static std::string decrypt_file_key_str(const char *wenc, const char *out,
                                        const u8_t *key) {
  FILE *fin = fopen(wenc, "rb");
  if (!fin) return "";
  FILE *fout = fopen(out, "wb+");
  if (!fout) {
    fclose(fin);
    return "";
  }
  Settings s(0, 0, true);
  runcrypt r(fin, fout, (u8_t *)key, s, 4);
  try {
    r.execute_decrypt(0);
    return "";
  } catch (const char *errlog) {
    std::cout << errlog << std::endl;
    return errlog;
  } catch (std::string errlog) {
    std::cout << errlog << std::endl;
    return errlog;
  }
}

/* 新版接口: execute_verify 成功返回 (htype<<8)|ctype; 失败抛异常并填充 out_msg, 返回 0xFFFF */
static unsigned short verify_ret(const char *wenc, const u8_t *key,
                                 std::string &out_msg) {
  FILE *fp = fopen(wenc, "rb");
  if (!fp) { out_msg = "open failed"; return 0xFFFF; }
  Settings s(0, 0, true);
  runcrypt r(fp, NULL, (u8_t *)key, s, 4);
  try {
    out_msg.clear();
    return r.execute_verify(0);
  } catch (const char *errlog) {
    std::cout << errlog << std::endl;
    out_msg = errlog;
    return 0xFFFF;
  } catch (std::string errlog) {
    std::cout << errlog << std::endl;
    out_msg = errlog;
    return 0xFFFF;
  }
}

/* 新版接口: execute_decrypt 成功返回 (htype<<8)|ctype 并写出明文; 失败抛异常并填充 out_msg, 返回 0xFFFF */
static unsigned short decrypt_ret(const char *wenc, const char *out,
                                  const u8_t *key, std::string &out_msg) {
  FILE *fin = fopen(wenc, "rb");
  if (!fin) { out_msg = "open failed"; return 0xFFFF; }
  FILE *fout = fopen(out, "wb+");
  if (!fout) {
    fclose(fin);
    out_msg = "open out failed";
    return 0xFFFF;
  }
  Settings s(0, 0, true);
  runcrypt r(fin, fout, (u8_t *)key, s, 4);
  try {
    out_msg.clear();
    return r.execute_decrypt(0);
  } catch (const char *errlog) {
    std::cout << errlog << std::endl;
    out_msg = errlog;
    return 0xFFFF;
  } catch (std::string errlog) {
    std::cout << errlog << std::endl;
    out_msg = errlog;
    return 0xFFFF;
  }
}

TEST(Testboundary, verify_valid) {
  ASSERT_TRUE(encrypt_small("tb_ok.txt", "tb_ok.wenc", 1, 0));
  EXPECT_TRUE(verify_file("tb_ok.wenc"));
  EXPECT_EQ("", verify_file_str("tb_ok.wenc"));
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
  EXPECT_EQ("Wrong magic number.", verify_file_str("tb_bm.wenc"));
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
  EXPECT_EQ("Wrong key or File not complete.", verify_file_str("tb_cd.wenc"));
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
  EXPECT_EQ("Wrong key or File not complete.", verify_file_str("tb_tr.short"));
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
  EXPECT_EQ("Input file is too short.", verify_file_str("tb_ts.wenc"));
  remove("tb_ts.wenc");
}

TEST(Testboundary, verify_wrong_key) {
  ASSERT_TRUE(encrypt_small("tb_vwk.txt", "tb_vwk.wenc", 1, 0));
  static const u8_t BADKEY[16] = {'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x',
                                  'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x'};
  EXPECT_FALSE(verify_file_key_str("tb_vwk.wenc", BADKEY).empty());
  EXPECT_EQ("Wrong key or File not complete.",
            verify_file_key_str("tb_vwk.wenc", BADKEY));
  remove("tb_vwk.txt");
  remove("tb_vwk.wenc");
}

TEST(Testboundary, verify_bad_mode_byte) {
  ASSERT_TRUE(encrypt_small("tb_vmd.txt", "tb_vmd.wenc", 1, 0));
  FILE *fp = fopen("tb_vmd.wenc", "rb+");
  ASSERT_TRUE(fp != NULL);
  u8_t h = 9; /* htype 9 > 2 */
  fseek(fp, 9, SEEK_SET);
  fwrite(&h, 1, 1, fp);
  fclose(fp);
  EXPECT_FALSE(verify_file("tb_vmd.wenc"));
  EXPECT_EQ("Aes / hash mode not match.", verify_file_str("tb_vmd.wenc"));
  remove("tb_vmd.txt");
  remove("tb_vmd.wenc");
}

/*################################
  新版解密异常路径 (execute_decrypt)
################################*/

/*################################
  新版解密/验证返回值 (execute_decrypt/execute_verify)
################################*/

TEST(Testboundary, verify_returns_mode_combo) {
  static const u8_t combos[][2] = {{0, 0}, {1, 0}, {2, 0}, {3, 0},
                                   {4, 0}, {1, 1}, {1, 2}, {2, 2}};
  char txt[64], wenc[64];
  for (size_t k = 0; k < sizeof(combos) / sizeof(combos[0]); ++k) {
    u8_t ctype = combos[k][0], htype = combos[k][1];
    snprintf(txt, sizeof txt, "tb_vr_%zu.txt", k);
    snprintf(wenc, sizeof wenc, "tb_vr_%zu.wenc", k);
    ASSERT_TRUE(encrypt_small(txt, wenc, ctype, htype))
        << "ctype=" << (int)ctype << " htype=" << (int)htype;
    std::string msg;
    unsigned short ret = verify_ret(wenc, TKEY, msg);
    EXPECT_EQ("", msg) << "ctype=" << (int)ctype << " htype=" << (int)htype;
    EXPECT_EQ((unsigned short)((htype << 8) | ctype), ret)
        << "ctype=" << (int)ctype << " htype=" << (int)htype;
    remove(txt);
    remove(wenc);
  }
}

TEST(Testboundary, decrypt_returns_mode_combo) {
  static const u8_t combos[][2] = {{0, 0}, {1, 0}, {2, 0}, {3, 0},
                                   {4, 0}, {1, 1}, {1, 2}, {2, 2}};
  char txt[64], wenc[64], out[64];
  for (size_t k = 0; k < sizeof(combos) / sizeof(combos[0]); ++k) {
    u8_t ctype = combos[k][0], htype = combos[k][1];
    snprintf(txt, sizeof txt, "tb_dr_%zu.txt", k);
    snprintf(wenc, sizeof wenc, "tb_dr_%zu.wenc", k);
    snprintf(out, sizeof out, "tb_dr_%zu.out", k);
    ASSERT_TRUE(encrypt_small(txt, wenc, ctype, htype))
        << "ctype=" << (int)ctype << " htype=" << (int)htype;
    std::string msg;
    unsigned short ret = decrypt_ret(wenc, out, TKEY, msg);
    EXPECT_EQ("", msg) << "ctype=" << (int)ctype << " htype=" << (int)htype;
    EXPECT_EQ((unsigned short)((htype << 8) | ctype), ret)
        << "ctype=" << (int)ctype << " htype=" << (int)htype;
    FILE *f1 = fopen(txt, "rb"), *f2 = fopen(out, "rb");
    EXPECT_EQ(1, cmp_file(f1, f2))
        << "ctype=" << (int)ctype << " htype=" << (int)htype;
    remove(txt);
    remove(wenc);
    remove(out);
  }
}

TEST(Testboundary, decrypt_bad_magic) {
  ASSERT_TRUE(encrypt_small("tb_dbm.txt", "tb_dbm.wenc", 1, 0));
  FILE *fp = fopen("tb_dbm.wenc", "rb+");
  ASSERT_TRUE(fp != NULL);
  u8_t z = 0;
  fwrite(&z, 1, 1, fp);
  fclose(fp);
  EXPECT_EQ("Wrong magic number.",
            decrypt_file_key_str("tb_dbm.wenc", "tb_dbm.out", TKEY));
  remove("tb_dbm.txt");
  remove("tb_dbm.wenc");
  remove("tb_dbm.out");
}

TEST(Testboundary, decrypt_corrupt_data) {
  ASSERT_TRUE(encrypt_small("tb_dcd.txt", "tb_dcd.wenc", 1, 0));
  FILE *fp = fopen("tb_dcd.wenc", "rb+");
  ASSERT_TRUE(fp != NULL);
  fseek(fp, FILE_TEXT_MARK(4) + 5, SEEK_SET);
  u8_t c;
  fread(&c, 1, 1, fp);
  fseek(fp, -1, SEEK_CUR);
  c ^= 0xff;
  fwrite(&c, 1, 1, fp);
  fclose(fp);
  EXPECT_EQ("Wrong key or File not complete.",
            decrypt_file_key_str("tb_dcd.wenc", "tb_dcd.out", TKEY));
  remove("tb_dcd.txt");
  remove("tb_dcd.wenc");
  remove("tb_dcd.out");
}

TEST(Testboundary, decrypt_wrong_key) {
  ASSERT_TRUE(encrypt_small("tb_dwk.txt", "tb_dwk.wenc", 1, 0));
  static const u8_t BADKEY[16] = {'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x',
                                  'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x'};
  EXPECT_EQ("Wrong key or File not complete.",
            decrypt_file_key_str("tb_dwk.wenc", "tb_dwk.out", BADKEY));
  remove("tb_dwk.txt");
  remove("tb_dwk.wenc");
  remove("tb_dwk.out");
}

TEST(Testboundary, decrypt_bad_mode_byte) {
  ASSERT_TRUE(encrypt_small("tb_dmd.txt", "tb_dmd.wenc", 1, 0));
  FILE *fp = fopen("tb_dmd.wenc", "rb+");
  ASSERT_TRUE(fp != NULL);
  u8_t h = 9; /* htype 9 > 2 */
  fseek(fp, 9, SEEK_SET);
  fwrite(&h, 1, 1, fp);
  fclose(fp);
  EXPECT_EQ("Aes / hash mode not match.",
            decrypt_file_key_str("tb_dmd.wenc", "tb_dmd.out", TKEY));
  remove("tb_dmd.txt");
  remove("tb_dmd.wenc");
  remove("tb_dmd.out");
}

TEST(Testboundary, decrypt_too_short) {
  FILE *fp = fopen("tb_dts.wenc", "wb");
  ASSERT_TRUE(fp != NULL);
  u8_t z[10] = {0};
  fwrite(z, 1, 10, fp);
  fclose(fp);
  EXPECT_EQ("Input file is too short.",
            decrypt_file_key_str("tb_dts.wenc", "tb_dts.out", TKEY));
  remove("tb_dts.wenc");
  remove("tb_dts.out");
}

/*################################
  新版异常接口 (void + throw)
################################*/

TEST(Testboundary, exec_null_fin_throws) {
  Settings s(1, 0, true);
  runcrypt r_enc(NULL, NULL, (u8_t *)TKEY, s, 4);
  EXPECT_THROW(r_enc.execute_encrypt(0, NULL), std::string);
  runcrypt r_dec(NULL, NULL, (u8_t *)TKEY, s, 4);
  EXPECT_THROW(r_dec.execute_decrypt(0), std::string);
  runcrypt r_ver(NULL, NULL, (u8_t *)TKEY, s, 4);
  EXPECT_THROW(r_ver.execute_verify(0), std::string);
}

TEST(Testboundary, exec_decrypt_bad_file_throws) {
  ASSERT_TRUE(encrypt_small("tb_dc.txt", "tb_dc.wenc", 1, 0));
  FILE *fp = fopen("tb_dc.wenc", "rb+");
  ASSERT_TRUE(fp != NULL);
  fseek(fp, FILE_TEXT_MARK(4) + 3, SEEK_SET);
  u8_t c;
  fread(&c, 1, 1, fp);
  fseek(fp, -1, SEEK_CUR);
  c ^= 0xff;
  fwrite(&c, 1, 1, fp);
  fclose(fp);
  FILE *fin = fopen("tb_dc.wenc", "rb"), *fout = fopen("tb_dc.out", "wb+");
  ASSERT_TRUE(fin != NULL && fout != NULL);
  Settings s(0, 0, true);
  runcrypt r(fin, fout, (u8_t *)TKEY, s, 4);
  EXPECT_THROW(r.execute_decrypt(0), std::string);
  remove("tb_dc.txt");
  remove("tb_dc.wenc");
  remove("tb_dc.out");
}

/*################################
  多块流水线:冗余缓冲排空收尾路径
  单个 chunk 为 16MB,≥5 块(>64MB)文件会迫使同一工作线程在 read_done 后
  仍需排空多个同时 LOADED 的块。此路径修复前会因 worker 处理完一块即提前
  退出,将名下剩余块遗弃,导致写线程在 judge_buffer_full 上永久死锁。
################################*/

TEST(Testboundary, multi_chunk_pipeline) {
  // 65MB ≈ 5 个 16MB chunk:线程 0 名下至少两块同时在读线程 EOF 时处于 LOADED
  static const size_t SIZE = 0x4100000;
  EXPECT_EQ(1, thread_roundtrip(SIZE, 2, 1, 0)) << "threads=2 cbc";
  EXPECT_EQ(1, thread_roundtrip(SIZE, 4, 1, 0)) << "threads=4 cbc";
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
