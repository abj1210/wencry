#include "getval.h"
#include "valhelper.h"
#include "testutil.h"
#include "gtest/gtest.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static const u8_t key[16] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                             '0', '1', '2', '3', '4', '5', '6', '7'};

static u8_t *run_getopt(const std::vector<std::string> &args) {
  std::vector<std::string> full;
  full.push_back("wencry");
  for (const auto &a : args)
    full.push_back(a);
  std::vector<char *> argv;
  for (auto &a : full)
    argv.push_back(a.data());
  return getCommandLineArgs((int)argv.size(), argv.data());
}

static void free_vpak(u8_t *v) {
  if (v == NULL)
    return;
  vpak_t *p = (vpak_t *)v;
  if (p->fp != NULL)
    fclose(p->fp);
  if (p->out != NULL)
    fclose(p->out);
  delete[] p->key;
  delete p;
}

static std::string make_input(const char *content) {
  char name[64];
  make_tmp_name(name, sizeof(name), "gopt");
  FILE *f = fopen(name, "wb");
  fwrite(content, 1, strlen(content), f);
  fclose(f);
  return std::string(name);
}

TEST(Testgetopt, no_mode_rejected) {
  EXPECT_TRUE(run_getopt({}) == NULL);
}

TEST(Testgetopt, encrypt_requires_input) {
  EXPECT_TRUE(run_getopt({"-e"}) == NULL);
}

TEST(Testgetopt, decrypt_requires_key) {
  EXPECT_TRUE(run_getopt({"-d"}) == NULL);
}

TEST(Testgetopt, multiple_modes_rejected) {
  EXPECT_TRUE(run_getopt({"-e", "-d"}) == NULL);
}

TEST(Testgetopt, invalid_key_rejected) {
  EXPECT_TRUE(run_getopt({"-d", "-k", "!!!"}) == NULL);
}

TEST(Testgetopt, invalid_ctype_rejected) {
  std::string in = make_input("abc");
  EXPECT_TRUE(run_getopt({"-e", "-i", in, "--cmode", "9"}) == NULL);
  remove(in.c_str());
}

TEST(Testgetopt, invalid_hmode_rejected) {
  std::string in = make_input("abc");
  EXPECT_TRUE(run_getopt({"-e", "-i", in, "--hmode", "9"}) == NULL);
  remove(in.c_str());
}

TEST(Testgetopt, double_key_rejected) {
  std::string in = make_input("abc");
  std::string kb64 = printKey((u8_t *)key);
  EXPECT_TRUE(run_getopt({"-e", "-i", in, "-k", kb64, "-k", kb64}) == NULL);
  remove(in.c_str());
}

TEST(Testgetopt, double_ctype_rejected) {
  std::string in = make_input("abc");
  EXPECT_TRUE(run_getopt({"-e", "-i", in, "--cmode", "1", "--cmode", "2"}) == NULL);
  remove(in.c_str());
}

TEST(Testgetopt, double_hmode_rejected) {
  std::string in = make_input("abc");
  EXPECT_TRUE(run_getopt({"-e", "-i", in, "--hmode", "0", "--hmode", "2"}) == NULL);
  remove(in.c_str());
}

TEST(Testgetopt, unknown_option_rejected) {
  EXPECT_TRUE(run_getopt({"-e", "--bogus"}) == NULL);
}

TEST(Testgetopt, missing_input_file_rejected) {
  EXPECT_TRUE(run_getopt({"-e", "-i", "/nonexistent/wencry_no_file"}) == NULL);
}

TEST(Testgetopt, unwritable_output_rejected) {
  std::string in = make_input("abc");
  EXPECT_TRUE(run_getopt({"-e", "-i", in, "-o", "/nonexistent_dir/out.wenc"}) == NULL);
  remove(in.c_str());
}

TEST(Testgetopt, encrypt_explicit_options) {
  std::string in = make_input("hello wencry");
  std::string out = in + ".out";
  std::string kb64 = printKey((u8_t *)key);

  u8_t *v = run_getopt({"-e", "-i", in, "-o", out, "-k", kb64,
                        "--cmode", "2", "--hmode", "2", "-n"});
  ASSERT_TRUE(v != NULL);
  vpak_t *p = (vpak_t *)v;
  EXPECT_EQ('e', p->mode);
  EXPECT_EQ(2, (int)p->ctype);
  EXPECT_EQ(2, (int)p->htype);
  EXPECT_TRUE(p->no_echo);
  EXPECT_TRUE(p->fp != NULL);
  EXPECT_TRUE(p->out != NULL);
  EXPECT_EQ(strlen("hello wencry"), p->size);
  EXPECT_EQ(0, memcmp(key, p->key, 16));
  free_vpak(v);

  remove(in.c_str());
  remove(out.c_str());
}

TEST(Testgetopt, encrypt_defaults) {
  std::string in = make_input("abc");
  u8_t *v = run_getopt({"-e", "-i", in});
  ASSERT_TRUE(v != NULL);
  vpak_t *p = (vpak_t *)v;
  EXPECT_EQ(1, (int)p->ctype);
  EXPECT_EQ(0, (int)p->htype);
  EXPECT_TRUE(p->key != NULL);
  EXPECT_TRUE(p->out != NULL);
  free_vpak(v);

  remove(in.c_str());
  remove((in + ".wenc").c_str());
}

TEST(Testgetopt, version_and_help) {
  u8_t *v = run_getopt({"-V"});
  ASSERT_TRUE(v != NULL);
  EXPECT_EQ('V', ((vpak_t *)v)->mode);
  free_vpak(v);

  v = run_getopt({"-h"});
  ASSERT_TRUE(v != NULL);
  EXPECT_EQ('h', ((vpak_t *)v)->mode);
  free_vpak(v);
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
