#include "hashtype.h"
#include "testutil.h"
#include "gtest/gtest.h"

void testspd(typehash * hasher, unsigned int size){
    hasher->reset();
    u8_t blk[64];
    while (true) {
        u64_t sum = 64;
        if(size < 64) sum =size;
        else size -= 64;
        if (sum != 64) {
            hasher->getHash(blk, sum);
            break;
        }
        hasher->getHash(blk);
    }
}
TEST(Testhashspd, testspd_sha1){
    typehash * hasher = new sha1hash();
    testspd(hasher, 128*1024*1024);
    delete hasher;
}

TEST(Testhashspd, testspd_md5){
    typehash * hasher = new md5hash();
    testspd(hasher, 128*1024*1024);
    delete hasher;
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}