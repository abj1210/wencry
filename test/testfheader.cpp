#include "fheader.h"
#include "testutil.h"
#include "gtest/gtest.h"

#include <cstdio>
#include <cstring>

static const u8_t key[16] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                             '0', '1', '2', '3', '4', '5', '6', '7'};

static void make_iv(u8_t *iv, u8_t num) {
  for (int i = 0; i < 20 * num; ++i)
    iv[i] = (u8_t)(i + 1);
}

/* 手工构造 48 字节文件头: 魔数(小端) + ctype + htype + padding(offset 47 记录 num)。 */
static void write_raw_header(const char *path, int ctype, int htype, u8_t num) {
  FILE *f = fopen(path, "wb");
  ASSERT_TRUE(f != NULL);
  const u8_t magic[8] = {0xC3, 0xA5, 0xC3, 0xA5, 0xC3, 0xA5, 0xC3, 0xA5};
  fwrite(magic, 1, 8, f);
  u8_t c = (u8_t)ctype;
  u8_t h = (u8_t)htype;
  fwrite(&c, 1, 1, f);
  fwrite(&h, 1, 1, f);
  u8_t pad[38];
  memset(pad, 0, sizeof(pad));
  pad[37] = num;
  fwrite(pad, 1, sizeof(pad), f);
  fclose(f);
}

TEST(Testfheader, build_and_parse) {
  char name[64];
  make_tmp_name(name, sizeof(name), "hdr");
  u8_t iv[20 * 4];
  make_iv(iv, 4);

  FILE *f = fopen(name, "wb");
  ASSERT_TRUE(f != NULL);
  FileHeader enc(f, f, (u8_t *)key, 2, 1, 4);
  enc.writeFileHeader(iv);
  fclose(f);

  f = fopen(name, "rb");
  ASSERT_TRUE(f != NULL);
  FileHeader dec(f, NULL, (u8_t *)key, 0);
  EXPECT_EQ(0, dec.checkHeader());
  dec.checkType();
  EXPECT_EQ(2, (int)dec.getCryptMode());
  EXPECT_EQ(1, (int)dec.getHashMode());
  EXPECT_EQ(4, (int)dec.getThreadNum());
  fclose(f);
  remove(name);
}

TEST(Testfheader, check_header_null_file) {
  FileHeader dec(NULL, NULL, (u8_t *)key, 0);
  EXPECT_EQ(4, dec.checkHeader());
}

TEST(Testfheader, check_header_too_short) {
  char name[64];
  make_tmp_name(name, sizeof(name), "short");
  FILE *f = fopen(name, "wb");
  const char *s = "0123456789";
  fwrite(s, 1, 10, f);
  fclose(f);

  f = fopen(name, "rb");
  FileHeader dec(f, NULL, (u8_t *)key, 0);
  EXPECT_EQ(1, dec.checkHeader());
  fclose(f);
  remove(name);
}

TEST(Testfheader, check_header_bad_magic) {
  char name[64];
  make_tmp_name(name, sizeof(name), "magic");
  FILE *f = fopen(name, "wb");
  u8_t buf[48];
  memset(buf, 0, sizeof(buf));
  fwrite(buf, 1, sizeof(buf), f);
  fclose(f);

  f = fopen(name, "rb");
  FileHeader dec(f, NULL, (u8_t *)key, 0);
  EXPECT_EQ(4, dec.checkHeader());
  fclose(f);
  remove(name);
}

TEST(Testfheader, check_header_bad_mode) {
  char name[64];
  make_tmp_name(name, sizeof(name), "mode");
  write_raw_header(name, 5, 0, 4);
  FILE *f = fopen(name, "rb");
  FileHeader dec(f, NULL, (u8_t *)key, 0);
  EXPECT_EQ(3, dec.checkHeader());
  fclose(f);
  remove(name);
}

TEST(Testfheader, thread_num_fallback) {
  char name[64];

  make_tmp_name(name, sizeof(name), "th0");
  write_raw_header(name, 1, 0, 0);
  FILE *f = fopen(name, "rb");
  FileHeader dec(f, NULL, (u8_t *)key, 0);
  dec.checkType();
  EXPECT_EQ(4, (int)dec.getThreadNum());
  fclose(f);
  remove(name);

  make_tmp_name(name, sizeof(name), "th20");
  write_raw_header(name, 1, 0, 20);
  f = fopen(name, "rb");
  FileHeader dec2(f, NULL, (u8_t *)key, 0);
  dec2.checkType();
  EXPECT_EQ(4, (int)dec2.getThreadNum());
  fclose(f);
  remove(name);
}

TEST(Testfheader, hmac_write_read) {
  char name[64];
  make_tmp_name(name, sizeof(name), "Hmac");
  u8_t iv[20 * 4];
  make_iv(iv, 4);

  FILE *f = fopen(name, "w+b");
  ASSERT_TRUE(f != NULL);
  FileHeader enc(f, f, (u8_t *)key, 2, 1, 4);
  enc.writeFileHeader(iv);
  u8_t Hmac[16];
  for (int i = 0; i < 16; ++i)
    Hmac[i] = (u8_t)(0xA0 + i);
  enc.writeHmac(Hmac, 16, 10);  // FILE_HMAC_MARK == 10
  fflush(f);

  u8_t *got = enc.getHmac(16);
  ASSERT_TRUE(got != NULL);
  EXPECT_EQ(0, memcmp(Hmac, got, 16));
  fclose(f);
  remove(name);
}

TEST(Testfheader, get_hmac_too_short) {
  char name[64];
  make_tmp_name(name, sizeof(name), "hshort");
  FILE *f = fopen(name, "wb");
  const char *s = "abc";
  fwrite(s, 1, 3, f);
  fclose(f);

  f = fopen(name, "rb");
  FileHeader dec(f, NULL, (u8_t *)key, 0);
  EXPECT_TRUE(dec.getHmac(16) == NULL);
  fclose(f);
  remove(name);
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
