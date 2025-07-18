#include <iomanip>
#include <iostream>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define USE_OPENSSL 1

#ifndef  USE_OPENSSL
//sudo apt-get install libcrypto++-dev libcrypto++-doc libcrypto++-utils
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <string>
#else
//sudo apt-get install libssl-dev
#include <iostream>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <string>
#include <iomanip>
#include <sstream>
#endif


// 定义常量
#define SM3_DIGEST_SIZE 32    // 摘要长度(字节)

// SM3上下文结构
typedef struct {
    uint32_t state[8];      // 中间状态
    uint64_t count;         // 已处理消息长度(位)
    uint8_t buffer[64];     // 当前分组
} SM3_CTX;

void sm3_init(SM3_CTX* ctx);
void sm3_update(SM3_CTX* ctx, const uint8_t* data, size_t len);
void sm3_final(SM3_CTX* ctx, uint8_t digest[SM3_DIGEST_SIZE]);


#define SM3_BLOCK_SIZE 64     // 分组长度(字节)

// 初始向量IV (大端序)
static const uint32_t IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

// 循环左移
static uint32_t ROTL(uint32_t X, int n) {
    return (X << n) | (X >> (32 - n));
}

// 布尔函数FFj
static uint32_t FFj(uint32_t X, uint32_t Y, uint32_t Z, int j) {
    return (j < 16) ? (X ^ Y ^ Z) : ((X & Y) | (X & Z) | (Y & Z));
}

// 布尔函数GGj
static uint32_t GGj(uint32_t X, uint32_t Y, uint32_t Z, int j) {
    return (j < 16) ? (X ^ Y ^ Z) : ((X & Y) | (~X & Z));
}

// 置换函数P0
static uint32_t P0(uint32_t X) {
    return X ^ ROTL(X, 9) ^ ROTL(X, 17);
}

// 置换函数P1
static uint32_t P1(uint32_t X) {
    return X ^ ROTL(X, 15) ^ ROTL(X, 23);
}

// 常量Tj
static uint32_t Tj(int j) {
    return (j < 16) ? 0x79CC4519 : 0x7A879D8A;
}

// 初始化上下文
void sm3_init(SM3_CTX* ctx) {
    memcpy(ctx->state, IV, sizeof(IV));
    ctx->count = 0;
    memset(ctx->buffer, 0, SM3_BLOCK_SIZE);
}

// 处理单个512位分组
static void sm3_compress(SM3_CTX* ctx, const uint8_t block[SM3_BLOCK_SIZE]) {
    uint32_t W[68];  // 消息扩展后的字
    uint32_t W1[64]; // 用于压缩的字
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t SS1, SS2, TT1, TT2;

    // 1. 消息扩展 (手动解析大端序)
    for (int i = 0; i < 16; i++) {
        W[i] = ((uint32_t)block[i * 4] << 24) |
            ((uint32_t)block[i * 4 + 1] << 16) |
            ((uint32_t)block[i * 4 + 2] << 8) |
            (uint32_t)block[i * 4 + 3];
    }
    for (int j = 16; j < 68; j++) {
        W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL(W[j - 3], 15))
            ^ ROTL(W[j - 13], 7) ^ W[j - 6];
    }
    for (int j = 0; j < 64; j++) {
        W1[j] = W[j] ^ W[j + 4];
    }

    // 2. 压缩函数
    A = ctx->state[0]; B = ctx->state[1]; C = ctx->state[2]; D = ctx->state[3];
    E = ctx->state[4]; F = ctx->state[5]; G = ctx->state[6]; H = ctx->state[7];

    for (int j = 0; j < 64; j++) {
        SS1 = ROTL((ROTL(A, 12) + E + ROTL(Tj(j), j)), 7);
        SS2 = SS1 ^ ROTL(A, 12);
        TT1 = FFj(A, B, C, j) + D + SS2 + W1[j];
        TT2 = GGj(E, F, G, j) + H + SS1 + W[j];

        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
    }

    // 3. 更新状态
    ctx->state[0] ^= A; ctx->state[1] ^= B;
    ctx->state[2] ^= C; ctx->state[3] ^= D;
    ctx->state[4] ^= E; ctx->state[5] ^= F;
    ctx->state[6] ^= G; ctx->state[7] ^= H;
}

// 更新消息数据
void sm3_update(SM3_CTX* ctx, const uint8_t* data, size_t len) {
    size_t left = ctx->count / 8 % SM3_BLOCK_SIZE;
    size_t fill = SM3_BLOCK_SIZE - left;

    ctx->count += len * 8; // 更新位计数

    // 处理不完整缓冲区
    if (left && len >= fill) {
        memcpy(ctx->buffer + left, data, fill);
        sm3_compress(ctx, ctx->buffer);
        data += fill;
        len -= fill;
        left = 0;
    }

    // 处理完整分组
    while (len >= SM3_BLOCK_SIZE) {
        sm3_compress(ctx, data);
        data += SM3_BLOCK_SIZE;
        len -= SM3_BLOCK_SIZE;
    }

    // 存储剩余数据
    if (len) {
        memcpy(ctx->buffer + left, data, len);
    }
}

// 生成最终摘要
void sm3_final(SM3_CTX* ctx, uint8_t digest[SM3_DIGEST_SIZE]) {
    size_t last = (ctx->count / 8) % SM3_BLOCK_SIZE;
    size_t padn = (last < 56) ? (56 - last) : (120 - last);

    // 填充数据: 0x80 + 0x00... + 消息长度(64位大端序)
    uint8_t footer[64] = { 0x80 };
    uint64_t bit_count = ctx->count;
    uint8_t len_bytes[8];

    // 手动构造大端序长度
    for (int i = 0; i < 8; i++) {
        len_bytes[i] = (bit_count >> (56 - 8 * i)) & 0xFF;
    }

    sm3_update(ctx, footer, padn);
    sm3_update(ctx, len_bytes, 8);

    // 输出大端序摘要
    for (int i = 0; i < 8; i++) {
        digest[4 * i] = (ctx->state[i] >> 24) & 0xFF;
        digest[4 * i + 1] = (ctx->state[i] >> 16) & 0xFF;
        digest[4 * i + 2] = (ctx->state[i] >> 8) & 0xFF;
        digest[4 * i + 3] = ctx->state[i] & 0xFF;
    }
}

#ifndef  USE_OPENSSL
std::string hmac_sha256_cryptopp(const std::string& key, const std::string& data) {
    using namespace CryptoPP;
    HMAC<SHA256> hmac((const byte*)key.data(), key.size());
    std::string result;
    StringSource ss1(data, true,
       new HashFilter(hmac,
          new HexEncoder(new StringSink(result))));
    return result;
}
#else
std::string hmac_sha256_openssl(const std::string& key, const std::string& data) {
    unsigned char* digest = HMAC(EVP_sha256(), key.data(), key.size(),
                                reinterpret_cast<const unsigned char*>(data.data()), data.size(), nullptr, nullptr);
    char md_string[2*EVP_MAX_MD_SIZE]; // 2 hex characters per byte
    for (int i = 0; i < EVP_MD_size(EVP_sha256()); ++i) {
        sprintf(&md_string[i*2], "%02x", digest[i]);
    }
    return std::string(md_string);
}

std::string hmac_sm3(const std::string& key, const std::string& data) {
    unsigned char* md = (unsigned char*)OPENSSL_malloc(EVP_MAX_MD_SIZE);
    unsigned int md_len;
    HMAC_CTX* ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key.c_str(), key.size(), EVP_sm3(), nullptr);
    HMAC_Update(ctx, reinterpret_cast<const unsigned char*>(data.c_str()), data.size());
    HMAC_Final(ctx, md, &md_len);
    HMAC_CTX_free(ctx);

    std::string result;
    for (unsigned int i = 0; i < md_len; i++) {
        char hex[3];
        sprintf(hex, "%02x", md[i]);
        result += hex;
    }
    OPENSSL_free(md);
    return result;
}

#endif

// 辅助函数：打印十六进制
void print_hex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]);
    }
    std::cout << std::dec << std::endl;
}

int main() {
    std::cout << "C++ SM3 HASH TEST:" << std::endl;
    SM3_CTX ctx;
    sm3_init(&ctx);
    // 测试SM3哈希
    const char* test_str = "Hello, HMAC-SM3!";
    uint8_t hash_result[32];
    sm3_update(&ctx,reinterpret_cast<const uint8_t*>(test_str),strlen(test_str));
    sm3_final(&ctx, hash_result);
    print_hex(hash_result, 32);
    //SM3-HASH
    //65460e63cd2e30b5b12a2fe821f934fddb282f6b596d397c3f5ebbc81ec1c9e6    --JAVA
    //65460e63cd2e30b5b12a2fe821f934fddb282f6b596d397c3f5ebbc81ec1c9e6    --C++
    //SM3-HMAC
    //2c2d7be4307a1a030c018f9ff34be0180369d209ca2965293150588c9669b7df    --JAVA
    //2c2d7be4307a1a030c018f9ff34be0180369d209ca2965293150588c9669b7df    --C++

    //使用第三方库openssl or cryptopp  注：第三方库不实现SM3
    //HMAC TEST for cryptopp  hmac
    std::string key = "secretKey"; // 密钥
    std::string data = "Hello, HMAC-SM3!"; // 要进行HMAC的数据
#ifndef  USE_OPENSSL
    std::string hmac1 = hmac_sha256_cryptopp(key, data);
    std::cout << "HMAC cryptopp SHA-256: " << hmac1 << std::endl;
#else
    //hmac_sha256
    std::string hmac_sha256_string = hmac_sha256_openssl(key, data);
    std::cout << "HMAC OPENSSL SHA-256: " << hmac_sha256_string << std::endl;
    //ba993015a6e3cee9d632f52144c69db853f7a04ca6335139d2d538d0e49ab30a     ---SHA256

    //hmac_sm3
    std::string hmac_sm3_string = hmac_sm3(key, data);
    std::cout << "HMAC OPENSSL SM3: " << hmac_sm3_string << std::endl;
    //2c2d7be4307a1a030c018f9ff34be0180369d209ca2965293150588c9669b7df     ---SM3
#endif

    //纯C++实现HMAC WITH SM3


    return 0;
}



