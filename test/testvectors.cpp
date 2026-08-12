#include "cry.h"
#include "aesmode.h"
#include "hashmaster.h"
#include "testutil.h"
#include "gtest/gtest.h"

/*################################
  辅助函数
################################*/

static void fill_pattern(u8_t *out, size_t len) {
  for (size_t i = 0; i < len; ++i)
    out[i] = (u8_t)(i % 251);
}

static void aes_blocks(bool isenc, int mode, const u8_t *key, const u8_t *iv,
                       u8_t *block, size_t blocks) {
  AesFactory af((u8_t *)key);
  Aesmode *m = af.createCryMaster(isenc, (u8_t)mode, iv);
  for (size_t i = 0; i < blocks; ++i)
    m->runcry(block + 16 * i);
  delete m;
}

/*################################
  FIPS-197 单块向量
################################*/

TEST(Testvectors, aes_fips197_enc) {
  u8_t key[16], pt[16], ct[16], cmp[16];
  gethex("000102030405060708090a0b0c0d0e0f", key);
  gethex("00112233445566778899aabbccddeeff", pt);
  gethex("69c4e0d86a7b0430d8cdb78070b4c55a", cmp);
  memcpy(ct, pt, 16);
  aes_blocks(true, 0, key, pt, ct, 1);
  EXPECT_TRUE(cmpstr(ct, cmp, 16));
}

TEST(Testvectors, aes_fips197_dec) {
  u8_t key[16], pt[16], ct[16], cmp[16];
  gethex("000102030405060708090a0b0c0d0e0f", key);
  gethex("00112233445566778899aabbccddeeff", cmp);
  gethex("69c4e0d86a7b0430d8cdb78070b4c55a", ct);
  memcpy(pt, ct, 16);
  aes_blocks(false, 0, key, ct, pt, 1);
  EXPECT_TRUE(cmpstr(pt, cmp, 16));
}

/*################################
  NIST SP 800-38A 模式向量 (128-bit)
################################*/

static const char sp_key[] = "2b7e151628aed2a6abf7158809cf4f3c";
static const char sp_iv[] = "000102030405060708090a0b0c0d0e0f";
static const char sp_pt[] =
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710";

static void check_nist_mode(int mode, const char *ivhex, const char *cthex,
                            bool enc) {
  u8_t key[16], iv[16], block[64], cmp[64];
  gethex(sp_key, key);
  gethex(ivhex, iv);
  gethex(enc ? sp_pt : cthex, block);
  gethex(enc ? cthex : sp_pt, cmp);
  aes_blocks(enc, mode, key, iv, block, 4);
  EXPECT_TRUE(cmpstr(block, cmp, 64)) << "mode=" << mode;
}

TEST(Testvectors, aes_ecb_nist) {
  check_nist_mode(0, "000102030405060708090a0b0c0d0e0f",
                  "3ad77bb40d7a3660a89ecaf32466ef97"
                  "f5d3d58503b9699de785895a96fdbaaf"
                  "43b1cd7f598ece23881b00e3ed030688"
                  "7b0c785e27e8ad3f8223207104725dd4",
                  true);
}
TEST(Testvectors, aes_cbc_nist) {
  check_nist_mode(1, sp_iv,
                  "7649abac8119b246cee98e9b12e9197d"
                  "5086cb9b507219ee95db113a917678b2"
                  "73bed6b8e3c1743b7116e69e22229516"
                  "3ff1caa1681fac09120eca307586e1a7",
                  true);
}
TEST(Testvectors, aes_ctr_nist) {
  check_nist_mode(2, "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                  "874d6191b620e3261bef6864990db6ce"
                  "9806f66b7970fdff8617187bb9fffdff"
                  "5ae4df3edbd5d35e5b4f09020db03eab"
                  "1e031dda2fbe03d1792170a0f3009cee",
                  true);
}
TEST(Testvectors, aes_cfb_nist) {
  check_nist_mode(3, sp_iv,
                  "3b3fd92eb72dad20333449f8e83cfb4a"
                  "c8a64537a0b3a93fcde3cdad9f1ce58b"
                  "26751f67a3cbb140b1808cf187a4f4df"
                  "c04b05357c5d1c0eeac4c66f9ff7f2e6",
                  true);
}
TEST(Testvectors, aes_ofb_nist) {
  check_nist_mode(4, sp_iv,
                  "3b3fd92eb72dad20333449f8e83cfb4a"
                  "7789508d16918f03f53c52dac54ed825"
                  "9740051e9c5fecf64344f7a82260edcc"
                  "304c6528f659c77866a510d9c1d6ae5e",
                  true);
}

/*################################
  解密方向已知答案 (SP 800-38A)
################################*/

TEST(Testvectors, aes_cbc_decrypt_nist) {
  check_nist_mode(1, sp_iv,
                  "7649abac8119b246cee98e9b12e9197d"
                  "5086cb9b507219ee95db113a917678b2"
                  "73bed6b8e3c1743b7116e69e22229516"
                  "3ff1caa1681fac09120eca307586e1a7",
                  false);
}
TEST(Testvectors, aes_ctr_decrypt_nist) {
  check_nist_mode(2, "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                  "874d6191b620e3261bef6864990db6ce"
                  "9806f66b7970fdff8617187bb9fffdff"
                  "5ae4df3edbd5d35e5b4f09020db03eab"
                  "1e031dda2fbe03d1792170a0f3009cee",
                  false);
}
TEST(Testvectors, aes_cfb_decrypt_nist) {
  check_nist_mode(3, sp_iv,
                  "3b3fd92eb72dad20333449f8e83cfb4a"
                  "c8a64537a0b3a93fcde3cdad9f1ce58b"
                  "26751f67a3cbb140b1808cf187a4f4df"
                  "c04b05357c5d1c0eeac4c66f9ff7f2e6",
                  false);
}
TEST(Testvectors, aes_ofb_decrypt_nist) {
  check_nist_mode(4, sp_iv,
                  "3b3fd92eb72dad20333449f8e83cfb4a"
                  "7789508d16918f03f53c52dac54ed825"
                  "9740051e9c5fecf64344f7a82260edcc"
                  "304c6528f659c77866a510d9c1d6ae5e",
                  false);
}

/*################################
  CTR 计数器多字节进位
################################*/

TEST(Testvectors, aes_ctr_carry) {
  u8_t key[16], iv[16], block[64], cmp[64];
  gethex("2b7e151628aed2a6abf7158809cf4f3c", key);
  gethex("000000000000000000000000fffffffe", iv);
  gethex(sp_pt, block);
  gethex("19349c288a689b7097ef8ead5f31d79f"
         "9decc4298cdb4779c055b775cfb1eb63"
         "5759b7d88cf209fea276cf653f4a4341"
         "837e18d6ab8113d3a67b557a0e27639f",
         cmp);
  aes_blocks(true, 2, key, iv, block, 4);
  EXPECT_TRUE(cmpstr(block, cmp, 64));
}

/*################################
  每线程独立 IV (createCryMaster 3 参)
################################*/

TEST(Testvectors, per_thread_iv_distinct) {
  u8_t key[16], pt[64], iv1[20], iv2[20];
  fill_pattern(key, 16);
  fill_pattern(pt, 64);
  fill_pattern(iv1, 20);
  fill_pattern(iv2, 20);
  iv2[0] ^= 0xff;
  AesFactory af(key);
  for (int m = 1; m <= 4; ++m) {
    u8_t a[64], b[64];
    memcpy(a, pt, 64);
    memcpy(b, pt, 64);
    Aesmode *ma = af.createCryMaster(true, (u8_t)m, iv1);
    Aesmode *mb = af.createCryMaster(true, (u8_t)m, iv2);
    for (int i = 0; i < 4; ++i) {
      ma->runcry(a + 16 * i);
      mb->runcry(b + 16 * i);
    }
    EXPECT_FALSE(cmpstr(a, b, 64)) << "mode " << m
                                   << " should differ per IV";
    delete ma;
    delete mb;
  }
  u8_t a[64], b[64];
  memcpy(a, pt, 64);
  memcpy(b, pt, 64);
  Aesmode *ma = af.createCryMaster(true, 0, iv1);
  Aesmode *mb = af.createCryMaster(true, 0, iv2);
  for (int i = 0; i < 4; ++i) {
    ma->runcry(a + 16 * i);
    mb->runcry(b + 16 * i);
  }
  EXPECT_TRUE(cmpstr(a, b, 64)) << "ECB ignores IV";
  delete ma;
  delete mb;
}

/*################################
  哈希填充边界 (0/1/55/56/57/63/64/65/1000)
################################*/

struct hv_t {
  size_t len;
  const char *sha1, *md5, *sha256;
};
static const hv_t hv_bounds[] = {
    {0, "da39a3ee5e6b4b0d3255bfef95601890afd80709",
     "d41d8cd98f00b204e9800998ecf8427e",
     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    {1, "5ba93c9db0cff93f52b521d7420e43f6eda2784f",
     "93b885adfe0da089cdf634904fd59f71",
     "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"},
    {55, "8ae2d46729cfe68ff927af5eec9c7d1b66d65ac2",
     "6912ee65fff2d9f9ce2508cddf8bcda0",
     "463eb28e72f82e0a96c0a4cc53690c571281131f672aa229e0d45ae59b598b59"},
    {56, "636e2ec698dac903498e648bd2f3af641d3c88cb",
     "51fdd1acda72405dfdfa03fcb85896d7",
     "da2ae4d6b36748f2a318f23e7ab1dfdf45acdc9d049bd80e59de82a60895f562"},
    {57, "7cb1330f35244b57437539253304ea78a6b7c443",
     "5320ef4c17ef34a0cf2db763338d25eb",
     "2fe741af801cc238602ac0ec6a7b0c3a8a87c7fc7d7f02a3fe03d1c12eac4d8f"},
    {63, "6d942da0c4392b123528f2905c713a3ce28364bd",
     "48a6295221902e8e0938f773a7185e72",
     "29af2686fd53374a36b0846694cc342177e428d1647515f078784d69cdb9e488"},
    {64, "c6138d514ffa2135bfce0ed0b8fac65669917ec7",
     "b2d3f56bc197fd985d5965079b5e7148",
     "fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108"},
    {65, "69bd728ad6e13cd76ff19751fde427b00e395746",
     "8bd7053801c768420faf816fadba971c",
     "4bfd2c8b6f1eec7a2afeb48b934ee4b2694182027e6d0fc075074f2fabb31781"},
    {1000, "c9c960a0b925474fab83942cc27d504fc24ac37b",
     "a24f1e3ef66950e1327f210e3997ba2c",
     "4e4c294b331f7a2099a379bec34b9f9fc03dc46ab465d998f4d683da53487e6d"},
};

TEST(Testvectors, sha1_padding_boundaries) {
  HashFactory hf;
  Hashmaster *h = hf.getHasher(HashFactory::SHA1);
  u8_t in[1000], dig[20], cmp[20];
  for (size_t k = 0; k < sizeof(hv_bounds) / sizeof(hv_bounds[0]); ++k) {
    fill_pattern(in, hv_bounds[k].len);
    h->getStringHash(in, (u32_t)hv_bounds[k].len, dig);
    gethex(hv_bounds[k].sha1, cmp);
    EXPECT_TRUE(cmpstr(dig, cmp, 20)) << "sha1 len=" << hv_bounds[k].len;
  }
  delete h;
}
TEST(Testvectors, md5_padding_boundaries) {
  HashFactory hf;
  Hashmaster *h = hf.getHasher(HashFactory::MD5);
  u8_t in[1000], dig[16], cmp[16];
  for (size_t k = 0; k < sizeof(hv_bounds) / sizeof(hv_bounds[0]); ++k) {
    fill_pattern(in, hv_bounds[k].len);
    h->getStringHash(in, (u32_t)hv_bounds[k].len, dig);
    gethex(hv_bounds[k].md5, cmp);
    EXPECT_TRUE(cmpstr(dig, cmp, 16)) << "md5 len=" << hv_bounds[k].len;
  }
  delete h;
}
TEST(Testvectors, sha256_padding_boundaries) {
  HashFactory hf;
  Hashmaster *h = hf.getHasher(HashFactory::SHA256);
  u8_t in[1000], dig[32], cmp[32];
  for (size_t k = 0; k < sizeof(hv_bounds) / sizeof(hv_bounds[0]); ++k) {
    fill_pattern(in, hv_bounds[k].len);
    h->getStringHash(in, (u32_t)hv_bounds[k].len, dig);
    gethex(hv_bounds[k].sha256, cmp);
    EXPECT_TRUE(cmpstr(dig, cmp, 32)) << "sha256 len=" << hv_bounds[k].len;
  }
  delete h;
}

/*################################
  HMAC 参考向量 (RFC 2202 / openssl)
################################*/

static void hmac_round(u8_t htype, const u8_t key[16], const char *data,
                       const char *exphex, size_t hlen) {
  FILE *fp = genfile(data);
  hmac h;
  u8_t res[32], cmp[32];
  memset(res, 0, sizeof(res));
  h.gethmac(htype, (u8_t *)key, fp, res);
  gethex(exphex, cmp);
  EXPECT_TRUE(cmpstr(res, cmp, (int)hlen)) << "htype=" << (int)htype;
  fclose(fp);
}

TEST(Testvectors, hmac_sha1_reference) {
  u8_t k0b[16], kjefe[16];
  memset(k0b, 0x0b, 16);
  memset(kjefe, 0, 16);
  memcpy(kjefe, "Jefe", 4);
  hmac_round(0, k0b, "Hi There", "675b0b3a1b4ddf4e124872da6c2f632bfed957e9", 20);
  hmac_round(0, kjefe, "what do ya want for nothing?",
             "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79", 20);
}
TEST(Testvectors, hmac_md5_reference) {
  u8_t k0b[16], kjefe[16];
  memset(k0b, 0x0b, 16);
  memset(kjefe, 0, 16);
  memcpy(kjefe, "Jefe", 4);
  hmac_round(1, k0b, "Hi There", "9294727a3638bb1c13f48ef8158bfc9d", 16);
  hmac_round(1, kjefe, "what do ya want for nothing?",
             "750c783e6ab0b503eaa86e310a5db738", 16);
}
TEST(Testvectors, hmac_sha256_reference) {
  u8_t k0b[16], kjefe[16];
  memset(k0b, 0x0b, 16);
  memset(kjefe, 0, 16);
  memcpy(kjefe, "Jefe", 4);
  hmac_round(2, k0b, "Hi There",
             "492ce020fe2534a5789dc3848806c78f4f6711397f08e7e7a12ca5a4483c8aa6",
             32);
  hmac_round(2, kjefe, "what do ya want for nothing?",
             "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
             32);
}

/*################################
  大缓冲重载路径 (>32MB, getStringHash 分块哈希)
################################*/

TEST(Testvectors, hashfile_refill) {
  const size_t N = (size_t)32 * 1024 * 1024 + 64;
  std::vector<u8_t> data(N);
  for (size_t i = 0; i < N; ++i)
    data[i] = (u8_t)(i % 251);
  HashFactory hf;
  Hashmaster *h = hf.getHasher(HashFactory::SHA256);
  u8_t dig[32], cmp[32];
  h->getStringHash(data.data(), (u32_t)N, dig);
  gethex("51a5ccc7f50b8ed811ce37d6049aacb5caef6629f17e33f0c952a4e0ed693bfd", cmp);
  EXPECT_TRUE(cmpstr(dig, cmp, 32));
  delete h;
}

/*################################
  getPercentage 逻辑回归测试
  修复前:100*(int)(a/t) 在进度<100%时恒返回0
################################*/

TEST(Testvectors, getPercentage_logic) {
  ResultPrint rp;
  rp.printpercentage("t", 50, 100);
  EXPECT_EQ(50, rp.getPercentage());
  rp.printpercentage("t", 50, 100);
  EXPECT_EQ(100, rp.getPercentage());
  rp.printpercentage("t", 10, 100);  // 110% -> 钳制
  EXPECT_EQ(100, rp.getPercentage());
  rp.resetPercentage();
  EXPECT_EQ(0, rp.getPercentage());

  NullResPrint np;
  np.printpercentage("t", 25, 100);
  EXPECT_EQ(25, np.getPercentage());
  np.resetPercentage();
  EXPECT_EQ(0, np.getPercentage());
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
