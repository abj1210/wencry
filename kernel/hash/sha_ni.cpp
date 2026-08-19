#include "sha_ni.h"
#include <string.h>

/*
K256:SHA-256 轮常数(前64个素数立方根的小数部分前32位)
以 4 个 u32 打包进一个 __m128i,供 sha256_ni_block 的 _mm_sha256rnds2 指令直接取用。
*/
static const __m128i K256[16] = {
    _mm_setr_epi32(0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U),
    _mm_setr_epi32(0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U),
    _mm_setr_epi32(0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U),
    _mm_setr_epi32(0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U),
    _mm_setr_epi32(0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU),
    _mm_setr_epi32(0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU),
    _mm_setr_epi32(0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U),
    _mm_setr_epi32(0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U),
    _mm_setr_epi32(0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U),
    _mm_setr_epi32(0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U),
    _mm_setr_epi32(0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U),
    _mm_setr_epi32(0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U),
    _mm_setr_epi32(0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U),
    _mm_setr_epi32(0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U),
    _mm_setr_epi32(0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U),
    _mm_setr_epi32(0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U)};


/*################################
  SHA1-NI 单块变换
################################*/
static void sha1_ni_block(u32_t h[5], const u8_t *data)
{
    const __m128i SHUF = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    const __m128i E_MASK = _mm_set_epi64x(0xFFFFFFFF00000000ULL, 0);
    __m128i abcd = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i *)&h[0]), 0x1B);
    __m128i e0 = _mm_set_epi32(h[4], 0, 0, 0);
    __m128i e1, msg0, msg1, msg2, msg3;
    __m128i ABCD_SAVE, E_SAVE;
    ABCD_SAVE = abcd;
    E_SAVE = e0;
    e0 = _mm_and_si128(e0, E_MASK);
    msg0 = _mm_loadu_si128((const __m128i *)(data + 0));
    msg0 = _mm_shuffle_epi8(msg0, SHUF);
    e0 = _mm_add_epi32(e0, msg0);
    e1 = abcd;
    abcd = _mm_sha1rnds4_epu32(abcd, e0, 0);
    msg1 = _mm_loadu_si128((const __m128i *)(data + 16));
    msg1 = _mm_shuffle_epi8(msg1, SHUF);
    e1 = _mm_sha1nexte_epu32(e1, msg1);
    e0 = abcd;
    abcd = _mm_sha1rnds4_epu32(abcd, e1, 0);
    msg0 = _mm_sha1msg1_epu32(msg0, msg1);
    msg2 = _mm_loadu_si128((const __m128i *)(data + 32));
    msg2 = _mm_shuffle_epi8(msg2, SHUF);
    e0 = _mm_sha1nexte_epu32(e0, msg2);
    e1 = abcd;
    abcd = _mm_sha1rnds4_epu32(abcd, e0, 0);
    msg1 = _mm_sha1msg1_epu32(msg1, msg2);
    msg0 = _mm_xor_si128(msg0, msg2);
    msg3 = _mm_loadu_si128((const __m128i *)(data + 48));
    msg3 = _mm_shuffle_epi8(msg3, SHUF);
    e1 = _mm_sha1nexte_epu32(e1, msg3);
    e0 = abcd;
    msg0 = _mm_sha1msg2_epu32(msg0, msg3);
    abcd = _mm_sha1rnds4_epu32(abcd, e1, 0);
    msg2 = _mm_sha1msg1_epu32(msg2, msg3);
    msg1 = _mm_xor_si128(msg1, msg3);
    e0 = _mm_sha1nexte_epu32(e0, msg0);
    e1 = abcd;
    msg1 = _mm_sha1msg2_epu32(msg1, msg0);
    abcd = _mm_sha1rnds4_epu32(abcd, e0, 0);
    msg3 = _mm_sha1msg1_epu32(msg3, msg0);
    msg2 = _mm_xor_si128(msg2, msg0);
    e1 = _mm_sha1nexte_epu32(e1, msg1);
    e0 = abcd;
    msg2 = _mm_sha1msg2_epu32(msg2, msg1);
    abcd = _mm_sha1rnds4_epu32(abcd, e1, 1);
    msg0 = _mm_sha1msg1_epu32(msg0, msg1);
    msg3 = _mm_xor_si128(msg3, msg1);
    e0 = _mm_sha1nexte_epu32(e0, msg2);
    e1 = abcd;
    msg3 = _mm_sha1msg2_epu32(msg3, msg2);
    abcd = _mm_sha1rnds4_epu32(abcd, e0, 1);
    msg1 = _mm_sha1msg1_epu32(msg1, msg2);
    msg0 = _mm_xor_si128(msg0, msg2);
    e1 = _mm_sha1nexte_epu32(e1, msg3);
    e0 = abcd;
    msg0 = _mm_sha1msg2_epu32(msg0, msg3);
    abcd = _mm_sha1rnds4_epu32(abcd, e1, 1);
    msg2 = _mm_sha1msg1_epu32(msg2, msg3);
    msg1 = _mm_xor_si128(msg1, msg3);
    e0 = _mm_sha1nexte_epu32(e0, msg0);
    e1 = abcd;
    msg1 = _mm_sha1msg2_epu32(msg1, msg0);
    abcd = _mm_sha1rnds4_epu32(abcd, e0, 1);
    msg3 = _mm_sha1msg1_epu32(msg3, msg0);
    msg2 = _mm_xor_si128(msg2, msg0);
    e1 = _mm_sha1nexte_epu32(e1, msg1);
    e0 = abcd;
    msg2 = _mm_sha1msg2_epu32(msg2, msg1);
    abcd = _mm_sha1rnds4_epu32(abcd, e1, 1);
    msg0 = _mm_sha1msg1_epu32(msg0, msg1);
    msg3 = _mm_xor_si128(msg3, msg1);
    e0 = _mm_sha1nexte_epu32(e0, msg2);
    e1 = abcd;
    msg3 = _mm_sha1msg2_epu32(msg3, msg2);
    abcd = _mm_sha1rnds4_epu32(abcd, e0, 2);
    msg1 = _mm_sha1msg1_epu32(msg1, msg2);
    msg0 = _mm_xor_si128(msg0, msg2);
    e1 = _mm_sha1nexte_epu32(e1, msg3);
    e0 = abcd;
    msg0 = _mm_sha1msg2_epu32(msg0, msg3);
    abcd = _mm_sha1rnds4_epu32(abcd, e1, 2);
    msg2 = _mm_sha1msg1_epu32(msg2, msg3);
    msg1 = _mm_xor_si128(msg1, msg3);
    e0 = _mm_sha1nexte_epu32(e0, msg0);
    e1 = abcd;
    msg1 = _mm_sha1msg2_epu32(msg1, msg0);
    abcd = _mm_sha1rnds4_epu32(abcd, e0, 2);
    msg3 = _mm_sha1msg1_epu32(msg3, msg0);
    msg2 = _mm_xor_si128(msg2, msg0);
    e1 = _mm_sha1nexte_epu32(e1, msg1);
    e0 = abcd;
    msg2 = _mm_sha1msg2_epu32(msg2, msg1);
    abcd = _mm_sha1rnds4_epu32(abcd, e1, 2);
    msg0 = _mm_sha1msg1_epu32(msg0, msg1);
    msg3 = _mm_xor_si128(msg3, msg1);
    e0 = _mm_sha1nexte_epu32(e0, msg2);
    e1 = abcd;
    msg3 = _mm_sha1msg2_epu32(msg3, msg2);
    abcd = _mm_sha1rnds4_epu32(abcd, e0, 2);
    msg1 = _mm_sha1msg1_epu32(msg1, msg2);
    msg0 = _mm_xor_si128(msg0, msg2);
    e1 = _mm_sha1nexte_epu32(e1, msg3);
    e0 = abcd;
    msg0 = _mm_sha1msg2_epu32(msg0, msg3);
    abcd = _mm_sha1rnds4_epu32(abcd, e1, 3);
    msg2 = _mm_sha1msg1_epu32(msg2, msg3);
    msg1 = _mm_xor_si128(msg1, msg3);
    e0 = _mm_sha1nexte_epu32(e0, msg0);
    e1 = abcd;
    msg1 = _mm_sha1msg2_epu32(msg1, msg0);
    abcd = _mm_sha1rnds4_epu32(abcd, e0, 3);
    msg3 = _mm_sha1msg1_epu32(msg3, msg0);
    msg2 = _mm_xor_si128(msg2, msg0);
    e1 = _mm_sha1nexte_epu32(e1, msg1);
    e0 = abcd;
    msg2 = _mm_sha1msg2_epu32(msg2, msg1);
    abcd = _mm_sha1rnds4_epu32(abcd, e1, 3);
    msg3 = _mm_xor_si128(msg3, msg1);
    e0 = _mm_sha1nexte_epu32(e0, msg2);
    e1 = abcd;
    msg3 = _mm_sha1msg2_epu32(msg3, msg2);
    abcd = _mm_sha1rnds4_epu32(abcd, e0, 3);
    e1 = _mm_sha1nexte_epu32(e1, msg3);
    e0 = abcd;
    abcd = _mm_sha1rnds4_epu32(abcd, e1, 3);
    e1 = e0;
    e0 = _mm_slli_epi32(e0, 30);
    e1 = _mm_srli_epi32(e1, 2);
    e0 = _mm_xor_si128(e0, e1);
    abcd = _mm_add_epi32(abcd, ABCD_SAVE);
    e0 = _mm_add_epi32(e0, E_SAVE);
    abcd = _mm_shuffle_epi32(abcd, 0x1B);
    _mm_storeu_si128((__m128i *)&h[0], abcd);
    h[4] = _mm_extract_epi32(e0, 3);
}

/*################################
  SHA256-NI 单块变换
################################*/
static void sha256_ni_block(u32_t h[8], const u8_t *data)
{
    const __m128i SHUF = _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);
    __m128i state0 = _mm_loadu_si128((const __m128i *)&h[0]);
    __m128i state1 = _mm_loadu_si128((const __m128i *)&h[4]);
    __m128i msgtmp4;
    state0 = _mm_shuffle_epi32(state0, 0xB1);
    state1 = _mm_shuffle_epi32(state1, 0x1B);
    msgtmp4 = state0;
    state0 = _mm_alignr_epi8(state0, state1, 8);
    state1 = _mm_blend_epi16(state1, msgtmp4, 0xF0);
    __m128i msg, msgtmp, msgtmp0, msgtmp1, msgtmp2, msgtmp3;
    __m128i ABEF_SAVE, CDGH_SAVE;
    ABEF_SAVE = state0;
    CDGH_SAVE = state1;
    msg = _mm_loadu_si128((const __m128i *)(data + 0));
    msg = _mm_shuffle_epi8(msg, SHUF);
    msgtmp0 = msg;
    msg = _mm_add_epi32(msg, K256[0]);
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg = _mm_loadu_si128((const __m128i *)(data + 16));
    msg = _mm_shuffle_epi8(msg, SHUF);
    msgtmp1 = msg;
    msg = _mm_add_epi32(msg, K256[1]);
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msgtmp0 = _mm_sha256msg1_epu32(msgtmp0, msgtmp1);
    msg = _mm_loadu_si128((const __m128i *)(data + 32));
    msg = _mm_shuffle_epi8(msg, SHUF);
    msgtmp2 = msg;
    msg = _mm_add_epi32(msg, K256[2]);
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msgtmp1 = _mm_sha256msg1_epu32(msgtmp1, msgtmp2);
    msg = _mm_loadu_si128((const __m128i *)(data + 48));
    msg = _mm_shuffle_epi8(msg, SHUF);
    msgtmp3 = msg;
    msg = _mm_add_epi32(msg, K256[3]);
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msgtmp = msgtmp3;
    msgtmp = _mm_alignr_epi8(msgtmp, msgtmp2, 4);
    msgtmp0 = _mm_add_epi32(msgtmp0, msgtmp);
    msgtmp0 = _mm_sha256msg2_epu32(msgtmp0, msgtmp3);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msgtmp2 = _mm_sha256msg1_epu32(msgtmp2, msgtmp3);
    msg = msgtmp0;
    msg = _mm_add_epi32(msg, K256[4]);
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msgtmp = msgtmp0;
    msgtmp = _mm_alignr_epi8(msgtmp, msgtmp3, 4);
    msgtmp1 = _mm_add_epi32(msgtmp1, msgtmp);
    msgtmp1 = _mm_sha256msg2_epu32(msgtmp1, msgtmp0);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msgtmp3 = _mm_sha256msg1_epu32(msgtmp3, msgtmp0);
    msg = msgtmp1;
    msg = _mm_add_epi32(msg, K256[5]);
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msgtmp = msgtmp1;
    msgtmp = _mm_alignr_epi8(msgtmp, msgtmp0, 4);
    msgtmp2 = _mm_add_epi32(msgtmp2, msgtmp);
    msgtmp2 = _mm_sha256msg2_epu32(msgtmp2, msgtmp1);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msgtmp0 = _mm_sha256msg1_epu32(msgtmp0, msgtmp1);
    msg = msgtmp2;
    msg = _mm_add_epi32(msg, K256[6]);
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msgtmp = msgtmp2;
    msgtmp = _mm_alignr_epi8(msgtmp, msgtmp1, 4);
    msgtmp3 = _mm_add_epi32(msgtmp3, msgtmp);
    msgtmp3 = _mm_sha256msg2_epu32(msgtmp3, msgtmp2);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msgtmp1 = _mm_sha256msg1_epu32(msgtmp1, msgtmp2);
    msg = msgtmp3;
    msg = _mm_add_epi32(msg, K256[7]);
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msgtmp = msgtmp3;
    msgtmp = _mm_alignr_epi8(msgtmp, msgtmp2, 4);
    msgtmp0 = _mm_add_epi32(msgtmp0, msgtmp);
    msgtmp0 = _mm_sha256msg2_epu32(msgtmp0, msgtmp3);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msgtmp2 = _mm_sha256msg1_epu32(msgtmp2, msgtmp3);
    msg = msgtmp0;
    msg = _mm_add_epi32(msg, K256[8]);
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msgtmp = msgtmp0;
    msgtmp = _mm_alignr_epi8(msgtmp, msgtmp3, 4);
    msgtmp1 = _mm_add_epi32(msgtmp1, msgtmp);
    msgtmp1 = _mm_sha256msg2_epu32(msgtmp1, msgtmp0);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msgtmp3 = _mm_sha256msg1_epu32(msgtmp3, msgtmp0);
    msg = msgtmp1;
    msg = _mm_add_epi32(msg, K256[9]);
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msgtmp = msgtmp1;
    msgtmp = _mm_alignr_epi8(msgtmp, msgtmp0, 4);
    msgtmp2 = _mm_add_epi32(msgtmp2, msgtmp);
    msgtmp2 = _mm_sha256msg2_epu32(msgtmp2, msgtmp1);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msgtmp0 = _mm_sha256msg1_epu32(msgtmp0, msgtmp1);
    msg = msgtmp2;
    msg = _mm_add_epi32(msg, K256[10]);
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msgtmp = msgtmp2;
    msgtmp = _mm_alignr_epi8(msgtmp, msgtmp1, 4);
    msgtmp3 = _mm_add_epi32(msgtmp3, msgtmp);
    msgtmp3 = _mm_sha256msg2_epu32(msgtmp3, msgtmp2);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msgtmp1 = _mm_sha256msg1_epu32(msgtmp1, msgtmp2);
    msg = msgtmp3;
    msg = _mm_add_epi32(msg, K256[11]);
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msgtmp = msgtmp3;
    msgtmp = _mm_alignr_epi8(msgtmp, msgtmp2, 4);
    msgtmp0 = _mm_add_epi32(msgtmp0, msgtmp);
    msgtmp0 = _mm_sha256msg2_epu32(msgtmp0, msgtmp3);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msgtmp2 = _mm_sha256msg1_epu32(msgtmp2, msgtmp3);
    msg = msgtmp0;
    msg = _mm_add_epi32(msg, K256[12]);
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msgtmp = msgtmp0;
    msgtmp = _mm_alignr_epi8(msgtmp, msgtmp3, 4);
    msgtmp1 = _mm_add_epi32(msgtmp1, msgtmp);
    msgtmp1 = _mm_sha256msg2_epu32(msgtmp1, msgtmp0);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msgtmp3 = _mm_sha256msg1_epu32(msgtmp3, msgtmp0);
    msg = msgtmp1;
    msg = _mm_add_epi32(msg, K256[13]);
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msgtmp = msgtmp1;
    msgtmp = _mm_alignr_epi8(msgtmp, msgtmp0, 4);
    msgtmp2 = _mm_add_epi32(msgtmp2, msgtmp);
    msgtmp2 = _mm_sha256msg2_epu32(msgtmp2, msgtmp1);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg = msgtmp2;
    msg = _mm_add_epi32(msg, K256[14]);
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msgtmp = msgtmp2;
    msgtmp = _mm_alignr_epi8(msgtmp, msgtmp1, 4);
    msgtmp3 = _mm_add_epi32(msgtmp3, msgtmp);
    msgtmp3 = _mm_sha256msg2_epu32(msgtmp3, msgtmp2);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg = msgtmp3;
    msg = _mm_add_epi32(msg, K256[15]);
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    state0 = _mm_add_epi32(state0, ABEF_SAVE);
    state1 = _mm_add_epi32(state1, CDGH_SAVE);
    state0 = _mm_shuffle_epi32(state0, 0x1B);
    state1 = _mm_shuffle_epi32(state1, 0xB1);
    msgtmp4 = state0;
    state0 = _mm_blend_epi16(state0, state1, 0xF0);
    state1 = _mm_alignr_epi8(state1, msgtmp4, 8);
    _mm_storeu_si128((__m128i *)&h[0], state0);
    _mm_storeu_si128((__m128i *)&h[4], state1);
}

/*################################
  类实现
################################*/
/*
sha1ni::getHash:用 SHA1-NI 指令处理一个64字节整块并累加长度
input:64字节输入块
*/
void sha1ni::getHash(const u8_t *input)
{
    sha1_ni_block(h, input);
    addtotal(64);
}

/*
sha256ni::getHash:用 SHA256-NI 指令处理一个64字节整块并累加长度
input:64字节输入块
*/
void sha256ni::getHash(const u8_t *input)
{
    sha256_ni_block(h, input);
    addtotal(64);
}
