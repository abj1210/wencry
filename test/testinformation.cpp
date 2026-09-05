#include "valhelper.h"
#include "display/silent_display.h"
#include "gtest/gtest.h"

TEST(Testinformation, crypt_modes) {
  WencryInformation wif;
  for (int i = 0; i < 5; ++i)
    EXPECT_TRUE(wif.checkCryptMode(i));
  EXPECT_FALSE(wif.checkCryptMode(-1));
  EXPECT_FALSE(wif.checkCryptMode(5));
  EXPECT_EQ("ECB", wif.getCryptModeName(0));
  EXPECT_EQ("OFB", wif.getCryptModeName(4));
  EXPECT_EQ("unknown", wif.getCryptModeName(5));
  EXPECT_EQ(5, wif.getCryptModeCount());
}

TEST(Testinformation, hash_modes) {
  WencryInformation wif;
  for (int i = 0; i < 3; ++i)
    EXPECT_TRUE(wif.checkHashMode(i));
  EXPECT_FALSE(wif.checkHashMode(-1));
  EXPECT_FALSE(wif.checkHashMode(3));
  EXPECT_EQ("sha1", wif.getHashModeName(0));
  EXPECT_EQ("sha256", wif.getHashModeName(2));
  EXPECT_EQ("unknown", wif.getHashModeName(3));
  EXPECT_EQ(3, wif.getHashModeCount());
}

TEST(Testinformation, type_lists) {
  WencryInformation wif;
  std::string cl = wif.getCryptModeList();
  std::string hl = wif.getHashModeList();
  EXPECT_NE(std::string::npos, cl.find("ECB"));
  EXPECT_NE(std::string::npos, cl.find("OFB"));
  EXPECT_NE(std::string::npos, hl.find("sha1"));
  EXPECT_NE(std::string::npos, hl.find("sha256"));
}

TEST(Testinformation, metadata) {
  WencryInformation wif;
  EXPECT_FALSE(wif.getVersion().empty());
  EXPECT_FALSE(wif.getBuildTime().empty());
  EXPECT_NE(std::string::npos, wif.getHelp().find("wencry"));
}

TEST(Testinformation, mode_name_tables) {
  EXPECT_STREQ("ECB", cryptModeName(0));
  EXPECT_STREQ("OFB", cryptModeName(4));
  EXPECT_STREQ("unknown", cryptModeName(5));
  EXPECT_STREQ("sha1", hashModeName(0));
  EXPECT_STREQ("sha256", hashModeName(2));
  EXPECT_STREQ("unknown", hashModeName(3));
}

TEST(Testinformation, formatSize) {
  EXPECT_EQ("0.00 B", formatSize(0));
  EXPECT_EQ("1.00 KiB", formatSize(1024));
  EXPECT_EQ("1.00 MiB", formatSize(1024 * 1024));
}

TEST(Testinformation, result_strings_and_progress) {
  SilentDisplay d;
  EXPECT_EQ("Verification passed!", d.getResultString(0));
  EXPECT_EQ("Input file is too short.", d.getResultString(1));
  EXPECT_EQ("Wrong key or File not complete.", d.getResultString(2));
  EXPECT_EQ("Aes / hash mode not match.", d.getResultString(3));
  EXPECT_EQ("Wrong magic number.", d.getResultString(4));
  EXPECT_EQ(0, d.getPercentage());
  d.printPercentage("", 30, 100);
  d.printPercentage("", 20, 100);
  EXPECT_EQ(50, d.getPercentage());
  EXPECT_FALSE(d.isOver());
  d.printEncryptDone();
  EXPECT_TRUE(d.isOver());
}

TEST(Testinformation, unknown_result_string) {
  SilentDisplay d;
  EXPECT_EQ("Unknown res number: 99", d.getResultString(99));
}

TEST(Testinformation, percentage_clamp) {
  SilentDisplay d;
  d.printPercentage("", 200, 10);
  EXPECT_EQ(100, d.getPercentage());
  d.printPercentage("", 0, 0);
  EXPECT_EQ(0, d.getPercentage());
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
