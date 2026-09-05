#include "valhelper.h"
#include "testutil.h"
#include "gtest/gtest.h"

#include <cstdio>
#include <cstring>

TEST(Testvalhelper, process_mode) {
  EXPECT_EQ(0, getProcessMode('e'));
  EXPECT_EQ(0, getProcessMode('E'));
  EXPECT_EQ(1, getProcessMode('d'));
  EXPECT_EQ(1, getProcessMode('D'));
  EXPECT_EQ(2, getProcessMode('v'));
  EXPECT_EQ(-1, getProcessMode('V'));
  EXPECT_EQ(-1, getProcessMode('x'));
}

TEST(Testvalhelper, key_base64_roundtrip) {
  u8_t key[16] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                  '0', '1', '2', '3', '4', '5', '6', '7'};
  std::string b64 = printKey(key);
  EXPECT_EQ(24u, b64.size());
  u8_t out[16] = {0};
  EXPECT_TRUE(checkBase64Key((const u8_t *)b64.c_str(), out));
  EXPECT_EQ(0, memcmp(key, out, 16));
}

TEST(Testvalhelper, invalid_base64_key) {
  u8_t out[16] = {0};
  EXPECT_FALSE(checkBase64Key((const u8_t *)"!!!", out));
  EXPECT_FALSE(checkBase64Key((const u8_t *)"YWJj", out));
  EXPECT_FALSE(checkBase64Key((const u8_t *)"", out));
}

TEST(Testvalhelper, file_open_and_preallocate) {
  char name[64];
  make_tmp_name(name, sizeof(name), "fio");

  FILE *w = wencryOpenWrite(name);
  ASSERT_TRUE(w != NULL);
  const char *data = "hello";
  fwrite(data, 1, 5, w);
  fflush(w);
  EXPECT_TRUE(wencryPreallocate(w, 100));
  fseek(w, 0, SEEK_END);
  EXPECT_EQ(100L, ftell(w));
  fclose(w);

  FILE *r = wencryOpenRead(name);
  ASSERT_TRUE(r != NULL);
  char buf[16] = {0};
  size_t n = fread(buf, 1, sizeof(buf), r);
  EXPECT_GE(n, 5u);
  EXPECT_EQ(0, memcmp(buf, data, 5));
  fclose(r);

  EXPECT_TRUE(wencryPreallocate(NULL, 0));
  EXPECT_TRUE(wencryOpenRead("/nonexistent/wencry_no_such_file") == NULL);
  remove(name);
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
