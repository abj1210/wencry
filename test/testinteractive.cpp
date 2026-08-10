#include "cry.h"
#include "getval.h"
#include "test.h"
#include "testutil.h"
#include "gtest/gtest.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <cstdlib>

#ifdef _WIN32
#include <process.h>
#else
#include <sys/wait.h>
#include <unistd.h>
#endif

/*################################
  辅助函数
################################*/

static bool file_exists(const char *p) {
  FILE *f = fopen(p, "rb");
  if (f) {
    fclose(f);
    return true;
  }
  return false;
}

static std::string bin_path() {
#ifdef WENCRY_BIN
  return std::string(WENCRY_BIN);
#else
  if (file_exists("../Wencry"))
    return "../Wencry";
  if (file_exists("../Wencry.exe"))
    return "../Wencry.exe";
  return "../Wencry";
#endif
}

/*
run_bin:以脚本驱动真实 Wencry 二进制(交互式 get_v_mod1)
script:输入脚本内容
logfile:stdout/stderr 输出文件
return:进程退出码(-1 表示异常)
*/
static int run_bin(const char *script, const std::string &logfile) {
  char scriptfile[64];
  make_tmp_name(scriptfile, sizeof scriptfile, "script");
  FILE *fp = fopen(scriptfile, "wb");
  if (fp == NULL)
    return -1;
  fputs(script, fp);
  fclose(fp);
  std::string cmd = std::string("\"") + bin_path() + "\" < \"" + scriptfile +
                    "\" > \"" + logfile + "\" 2>&1";
  int rc = system(cmd.c_str());
  remove(scriptfile);
#ifdef _WIN32
  return rc;
#else
  if (WIFEXITED(rc))
    return WEXITSTATUS(rc);
  return -1;
#endif
}

/* CLI 解密(进程内) */
static bool cli_decrypt(const char *in, const char *out, const char *key) {
  const char *name = "./wencry";
  const char *a[] = {name, "-d", "-i", in, "-o", out, "-k", key, "-n"};
  return exec(9, (char **)a);
}

/* CLI 加密(进程内), 返回是否成功 */
static bool cli_encrypt(const char *in, const char *out, const char *cmode,
                        const char *hmode, const char *key) {
  const char *name = "./wencry";
  const char *a[] = {name, "-e", "-i", in, "-o", out, "--cmode", cmode,
                     "--hmode", hmode, "-k", key, "-n"};
  return exec(13, (char **)a);
}

/* 从日志提取 printkey 打印的 24 位 base64 密钥 */
static std::string extract_key(const std::string &log) {
  auto isb64 = [](char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '+' || c == '/';
  };
  for (size_t i = 0; i + 24 <= log.size(); ++i) {
    bool ok = true;
    for (int k = 0; k < 24; ++k)
      if (log[i + k] != '=' && !isb64(log[i + k])) {
        ok = false;
        break;
      }
    if (ok)
      return log.substr(i, 24);
  }
  return "";
}

/*################################
  用例
################################*/

TEST(Testinteractive, encrypt_roundtrip) {
  char infile[64], out[64], log[64];
  make_tmp_name(infile, sizeof infile, "ia");
  make_tmp_name(out, sizeof out, "out");
  make_tmp_name(log, sizeof log, "log");
  write_pattern_file(infile, 300);
  std::string script = std::string("e\n") + infile +
                       "\nn\nABEiM0RVZneImaq7zN3u/w==\n1\n0\nrand\n";
  int rc = run_bin(script.c_str(), log);
  EXPECT_EQ(0, rc);
  std::string wenc = std::string(infile) + ".wenc";
  EXPECT_TRUE(file_exists(wenc.c_str()));
  ASSERT_TRUE(cli_decrypt(wenc.c_str(), out, "ABEiM0RVZneImaq7zN3u/w=="));
  FILE *f1 = fopen(infile, "rb"), *f2 = fopen(out, "rb");
  EXPECT_EQ(1, cmp_file(f1, f2));
  remove(infile);
  remove(wenc.c_str());
  remove(out);
  remove(log);
}

TEST(Testinteractive, encrypt_key_retry) {
  char infile[64], out[64], log[64];
  make_tmp_name(infile, sizeof infile, "ia");
  make_tmp_name(out, sizeof out, "out");
  make_tmp_name(log, sizeof log, "log");
  write_pattern_file(infile, 200);
  std::string script = std::string("e\n") + infile +
                       "\nn\nBADKEY\nABEiM0RVZneImaq7zN3u/w==\n1\n0\nrand\n";
  int rc = run_bin(script.c_str(), log);
  EXPECT_EQ(0, rc);
  std::string wenc = std::string(infile) + ".wenc";
  EXPECT_TRUE(file_exists(wenc.c_str()));
  ASSERT_TRUE(cli_decrypt(wenc.c_str(), out, "ABEiM0RVZneImaq7zN3u/w=="));
  FILE *f1 = fopen(infile, "rb"), *f2 = fopen(out, "rb");
  EXPECT_EQ(1, cmp_file(f1, f2));
  remove(infile);
  remove(wenc.c_str());
  remove(out);
  remove(log);
}

TEST(Testinteractive, decrypt_interactive) {
  char infile[64], out[64], log[64];
  make_tmp_name(infile, sizeof infile, "ia");
  make_tmp_name(out, sizeof out, "out");
  make_tmp_name(log, sizeof log, "log");
  write_pattern_file(infile, 200);
  char wenc[160];
  snprintf(wenc, sizeof wenc, "%s.wenc", infile);
  ASSERT_TRUE(cli_encrypt(infile, wenc, "1", "0", "ABEiM0RVZneImaq7zN3u/w=="));
  std::string script = std::string("d\n") + wenc + "\nn\nABEiM0RVZneImaq7zN3u/w==\n";
  int rc = run_bin(script.c_str(), log);
  EXPECT_EQ(0, rc);
  std::string outdec = std::string(wenc) + ".wdec";
  EXPECT_TRUE(file_exists(outdec.c_str()));
  FILE *f1 = fopen(infile, "rb"), *f2 = fopen(outdec.c_str(), "rb");
  EXPECT_EQ(1, cmp_file(f1, f2));
  remove(infile);
  remove(wenc);
  remove(outdec.c_str());
  remove(log);
}

TEST(Testinteractive, verify_interactive) {
  char infile[64], log[64];
  make_tmp_name(infile, sizeof infile, "ia");
  make_tmp_name(log, sizeof log, "log");
  write_pattern_file(infile, 100);
  char wenc[160];
  snprintf(wenc, sizeof wenc, "%s.wenc", infile);
  ASSERT_TRUE(cli_encrypt(infile, wenc, "1", "0", "ABEiM0RVZneImaq7zN3u/w=="));
  std::string script = std::string("v\n") + wenc + "\nABEiM0RVZneImaq7zN3u/w==\n";
  EXPECT_EQ(0, run_bin(script.c_str(), log));
  std::string bad = std::string("v\n") + wenc + "\nAAAAAAAAAAAAAAAAAAAAAA==\n";
  EXPECT_NE(0, run_bin(bad.c_str(), log));
  remove(infile);
  remove(wenc);
  remove(log);
}

TEST(Testinteractive, invalid_mode) {
  char infile[64], log[64];
  make_tmp_name(infile, sizeof infile, "ia");
  make_tmp_name(log, sizeof log, "log");
  write_pattern_file(infile, 100);
  std::string script = std::string("x\n") + infile + "\n";
  EXPECT_NE(0, run_bin(script.c_str(), log));
  remove(infile);
  remove(log);
}

TEST(Testinteractive, encrypt_random_key) {
  char infile[64], out[64], log[64];
  make_tmp_name(infile, sizeof infile, "ia");
  make_tmp_name(out, sizeof out, "out");
  make_tmp_name(log, sizeof log, "log");
  write_pattern_file(infile, 200);
  std::string script = std::string("e\n") + infile + "\ny\n1\n0\nrand\n";
  int rc = run_bin(script.c_str(), log);
  EXPECT_EQ(0, rc);
  std::string wenc = std::string(infile) + ".wenc";
  EXPECT_TRUE(file_exists(wenc.c_str()));
  FILE *lf = fopen(log, "rb");
  ASSERT_TRUE(lf != NULL);
  fseek(lf, 0, SEEK_END);
  long sz = ftell(lf);
  fseek(lf, 0, SEEK_SET);
  std::string content((size_t)sz, '\0');
  if (sz > 0)
    fread(&content[0], 1, (size_t)sz, lf);
  fclose(lf);
  std::string key = extract_key(content);
  ASSERT_FALSE(key.empty()) << "cannot extract key from log";
  ASSERT_TRUE(cli_decrypt(wenc.c_str(), out, key.c_str()));
  FILE *f1 = fopen(infile, "rb"), *f2 = fopen(out, "rb");
  EXPECT_EQ(1, cmp_file(f1, f2));
  remove(infile);
  remove(wenc.c_str());
  remove(out);
  remove(log);
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
