#include "aes_ni.h"

static inline __m128i AES_128_ASSIST(__m128i temp1, __m128i temp2) {
    __m128i temp3;
    temp2 = _mm_shuffle_epi32(temp2, 0xff);          // 关键步骤: 将temp2中的特定字节复制到整个128位
    temp3 = _mm_slli_si128(temp1, 0x4);              // 左移4字节
    temp1 = _mm_xor_si128(temp1, temp3);             // 异或
    temp3 = _mm_slli_si128(temp3, 0x4);              // 继续左移
    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128(temp3, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp1 = _mm_xor_si128(temp1, temp2);             // 与经过处理的temp2异或
    return temp1;
}

AesniHandle::AesniHandle(const u8_t * init_key){
    __m128i raw_key = _mm_loadu_si128((const __m128i*)init_key);
    __m128i temp1, temp2;
    temp1 = raw_key;
    key[0] = temp1;                         // 原始密钥就是第一个轮密钥

    // 循环生成后续的10个轮密钥 (总共需要10次迭代)
    // rcon 是每次迭代的轮常数
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x1);   // 轮常数 0x01
    temp1 = AES_128_ASSIST(temp1, temp2);
    key[1] = temp1;

    temp2 = _mm_aeskeygenassist_si128(temp1, 0x2);   // 轮常数 0x02
    temp1 = AES_128_ASSIST(temp1, temp2);
    key[2] = temp1;

    temp2 = _mm_aeskeygenassist_si128(temp1, 0x4);   // 轮常数 0x04
    temp1 = AES_128_ASSIST(temp1, temp2);
    key[3] = temp1;

    temp2 = _mm_aeskeygenassist_si128(temp1, 0x8);   // 轮常数 0x08
    temp1 = AES_128_ASSIST(temp1, temp2);
    key[4] = temp1;

    temp2 = _mm_aeskeygenassist_si128(temp1, 0x10);  // 轮常数 0x10
    temp1 = AES_128_ASSIST(temp1, temp2);
    key[5] = temp1;

    temp2 = _mm_aeskeygenassist_si128(temp1, 0x20);  // 轮常数 0x20
    temp1 = AES_128_ASSIST(temp1, temp2);
    key[6] = temp1;

    temp2 = _mm_aeskeygenassist_si128(temp1, 0x40);  // 轮常数 0x40
    temp1 = AES_128_ASSIST(temp1, temp2);
    key[7] = temp1;

    temp2 = _mm_aeskeygenassist_si128(temp1, 0x80);  // 轮常数 0x80
    temp1 = AES_128_ASSIST(temp1, temp2);
    key[8] = temp1;

    temp2 = _mm_aeskeygenassist_si128(temp1, 0x1b);  // 轮常数 0x1b
    temp1 = AES_128_ASSIST(temp1, temp2);
    key[9] = temp1;

    temp2 = _mm_aeskeygenassist_si128(temp1, 0x36);  // 轮常数 0x36
    temp1 = AES_128_ASSIST(temp1, temp2);
    key[10] = temp1;
}

__m128i EncryAes::runaes_128bit(__m128i w){
    // 初始轮密钥加
    w = _mm_xor_si128(w, key[0]);
    
    // 9轮完整的AESENC
    for (int i = 1; i <= 9; i++) {
        w = _mm_aesenc_si128(w, key[i]);
    }
    
    // 最后一轮使用AESENCLAST
    w = _mm_aesenclast_si128(w, key[10]);
    return w;
}

void DecryAes::aes128_inverse_keys(){
        // 第一个和最后一个轮密钥相同（白化密钥）
    invkey[0] = key[10];
    invkey[10] = key[0];
    
    // 中间的9个密钥需要经过 InvMixColumns 变换
    for (int i = 1; i <= 9; i++) {
        // 使用 AESIMC 指令（InvMixColumns）处理轮密钥
        invkey[i] = _mm_aesimc_si128(key[10 - i]);
    }

}

__m128i DecryAes::runaes_128bit(__m128i w){
    // 第1轮：AddRoundKey（使用第10个轮密钥）
    w = _mm_xor_si128(w, invkey[0]);
    
    // 中间9轮：AESDEC
    for (int i = 1; i <= 9; i++) {
        w = _mm_aesdec_si128(w, invkey[i]);
    }
    
    // 最后一轮：AESDECLAST
    w = _mm_aesdeclast_si128(w, invkey[10]);
    
    return w;
}