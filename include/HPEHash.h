#pragma once
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <algorithm>

/**
 ## HPEHash 专为HP项目设计的简易版Hash实现 / HPEHash: A Simplified Hash Implementation for HPE Project
 - 所属项目 / Associated Project ：HPE (High-Performance Encryption) / HPEHash / TunnelFile
 - 项目链接/Project Link ：https://github.com/Deepl-ysp/TunnelFile/tree/main/include
- 版本 / Version：1.0
- 作者 / Author ：Deepl-ysp (GitHub:https://github.com/Deepl-ysp)
- 创建时间 / Create Time：2026-06-03
- 最近更新 / Last Update：2026-06-03
- 许可证 / License：MIT License
- 使用示例：
 ```cpp
    HPEHash::HPEMD5 md5;
    md5.update("Hello, World!");
    std::string hash = md5.finalHex();
    std::vector<uint8_t> input = {0x01, 0x02, 0x03};
    size_t outputLength = 32; // 256 bits
    std::vector<uint8_t> shakeHash = HPEHash::HPEShake256::digest(input, outputLength);
 ```
 */
namespace HPEHash
{
    /**
    ### HPEMD5 专为HPE项目设计的MD5简易版实现 / HPEMD5: A Simplified MD5 Implementation for HPE Project
    - 所属项目 / Associated Project ：HPE (High-Performance Encryption) / HPEHash / TunnelFile
    - 项目链接/Project Link ：https://github.com/Deepl-ysp/TunnelFile/tree/main/include
    - 版本 / Version：1.0
    - 作者 / Author ：Deepl-ysp (GitHub:https://github.com/Deepl-ysp)
    - 创建时间 / Create Time：2026-06-03
    - 最近更新 / Last Update：2026-06-03
    - 许可证 / License：MIT License
    - 使用示例：
     ```cpp
     HPEHash::HPEMD5 md5;
     md5.update("Hello, World!");
     std::string hash = md5.finalHex();
     ```
     */
    class HPEMD5
    {
    public:
        typedef unsigned int size_type;
        HPEMD5();
        HPEMD5 &update(const unsigned char *input, size_type len);
        HPEMD5 &update(const std::string &input);
        std::string finalHex();

    private:
        void init();
        typedef unsigned char uint1;
        typedef unsigned int uint4;
        enum
        {
            blocksize = 64
        };
        void transform(const uint1 block[blocksize]);
        static void decode(uint4 output[], const uint1 input[], size_type len);
        static void encode(uint1 output[], const uint4 input[], size_type len);
        bool finalized;
        uint1 buffer[blocksize];
        uint4 count[2];
        uint4 state[4];
        std::string digestToHex();
        static inline uint4 F(uint4 x, uint4 y, uint4 z) { return (x & y) | (~x & z); }
        static inline uint4 G(uint4 x, uint4 y, uint4 z) { return (x & z) | (y & ~z); }
        static inline uint4 H(uint4 x, uint4 y, uint4 z) { return x ^ y ^ z; }
        static inline uint4 I(uint4 x, uint4 y, uint4 z) { return y ^ (x | ~z); }
        static inline uint4 rotateLeft(uint4 x, int n) { return (x << n) | (x >> (32 - n)); }
        static inline void FF(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac)
        {
            a = rotateLeft(a + F(b, c, d) + x + ac, s) + b;
        }
        static inline void GG(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac)
        {
            a = rotateLeft(a + G(b, c, d) + x + ac, s) + b;
        }
        static inline void HH(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac)
        {
            a = rotateLeft(a + H(b, c, d) + x + ac, s) + b;
        }
        static inline void II(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac)
        {
            a = rotateLeft(a + I(b, c, d) + x + ac, s) + b;
        }
    };

    /**
    ### HPEShake256 专为HPE项目设计的SHAKE256简易版实现 / HPEShake256: A SHAKE256 Implementation for HPE Project
    - 所属项目 / Associated Project ：HPE (High-Performance Encryption) / HPEHash / TunnelFile
    - 项目链接/Project Link ：https://github.com/Deepl-ysp/TunnelFile/tree/main/include
    - 版本 / Version：1.0
    - 作者 / Author ：Deepl-ysp (GitHub:https://github.com/Deepl-ysp)
    - 创建时间 / Create Time：2026-06-03
    - 最近更新 / Last Update：2026-06-03
    - 许可证 / License：MIT License
    - 使用示例：
     ```cpp
        std::vector<uint8_t> input = {0x01, 0x02, 0x03};
        size_t outputLength = 32; // 256 bits
        std::vector<uint8_t> hash = HPEHash::HPEShake256::digest(input, outputLength);
     ```
     */
    class HPEShake256
    {
    public:
        static std::vector<uint8_t> digest(const std::vector<uint8_t> &input, size_t outputLength);
        static std::vector<uint8_t> digest(const uint8_t *input, size_t inputLen, size_t outputLength);

    private:
        static const int KECCAK_RATE = 136;
        static const int KECCAK_CAPACITY = 168;
        static const int KECCAK_STATE_SIZE = 200;

        uint64_t state[25];
        uint8_t buffer[KECCAK_RATE];
        size_t bufferIndex;
        bool finalized;

        HPEShake256() : bufferIndex(0), finalized(false)
        {
            std::memset(state, 0, sizeof(state));
            std::memset(buffer, 0, sizeof(buffer));
        }

        void absorb(const std::vector<uint8_t> &input);
        void absorb(const uint8_t *input, size_t length);

        std::vector<uint8_t> squeeze(size_t outputLength);
        void xorBufferIntoState();
        void keccakF1600();
        static inline uint64_t rotl(uint64_t x, int n)
        {
            return (x << n) | (x >> (64 - n));
        }
    };
}

HPEHash::HPEMD5::HPEMD5() { init(); }

void HPEHash::HPEMD5::init()
{
    finalized = false;
    count[0] = 0;
    count[1] = 0;
    state[0] = 0x67452301;
    state[1] = 0xefcdab89;
    state[2] = 0x98badcfe;
    state[3] = 0x10325476;
}

void HPEHash::HPEMD5::decode(uint4 output[], const uint1 input[], size_type len)
{
    for (unsigned int i = 0, j = 0; j < len; i++, j += 4)
        output[i] = ((uint4)input[j]) | (((uint4)input[j + 1]) << 8) |
                    (((uint4)input[j + 2]) << 16) | (((uint4)input[j + 3]) << 24);
}

void HPEHash::HPEMD5::encode(uint1 output[], const uint4 input[], size_type len)
{
    for (size_type i = 0, j = 0; j < len; i++, j += 4)
    {
        output[j] = input[i] & 0xff;
        output[j + 1] = (input[i] >> 8) & 0xff;
        output[j + 2] = (input[i] >> 16) & 0xff;
        output[j + 3] = (input[i] >> 24) & 0xff;
    }
}

void HPEHash::HPEMD5::transform(const uint1 block[blocksize])
{
    uint4 a = state[0], b = state[1], c = state[2], d = state[3], x[16];
    decode(x, block, blocksize);
    FF(a, b, c, d, x[0], 7, 0xd76aa478);
    FF(d, a, b, c, x[1], 12, 0xe8c7b756);
    FF(c, d, a, b, x[2], 17, 0x242070db);
    FF(b, c, d, a, x[3], 22, 0xc1bdceee);
    FF(a, b, c, d, x[4], 7, 0xf57c0faf);
    FF(d, a, b, c, x[5], 12, 0x4787c62a);
    FF(c, d, a, b, x[6], 17, 0xa8304613);
    FF(b, c, d, a, x[7], 22, 0xfd469501);
    FF(a, b, c, d, x[8], 7, 0x698098d8);
    FF(d, a, b, c, x[9], 12, 0x8b44f7af);
    FF(c, d, a, b, x[10], 17, 0xffff5bb1);
    FF(b, c, d, a, x[11], 22, 0x895cd7be);
    FF(a, b, c, d, x[12], 7, 0x6b901122);
    FF(d, a, b, c, x[13], 12, 0xfd987193);
    FF(c, d, a, b, x[14], 17, 0xa679438e);
    FF(b, c, d, a, x[15], 22, 0x49b40821);
    GG(a, b, c, d, x[1], 5, 0xf61e2562);
    GG(d, a, b, c, x[6], 9, 0xc040b340);
    GG(c, d, a, b, x[11], 14, 0x265e5a51);
    GG(b, c, d, a, x[0], 20, 0xe9b6c7aa);
    GG(a, b, c, d, x[5], 5, 0xd62f105d);
    GG(d, a, b, c, x[10], 9, 0x2441453);
    GG(c, d, a, b, x[15], 14, 0xd8a1e681);
    GG(b, c, d, a, x[4], 20, 0xe7d3fbc8);
    GG(a, b, c, d, x[9], 5, 0x21e1cde6);
    GG(d, a, b, c, x[14], 9, 0xc33707d6);
    GG(c, d, a, b, x[3], 14, 0xf4d50d87);
    GG(b, c, d, a, x[8], 20, 0x455a14ed);
    GG(a, b, c, d, x[13], 5, 0xa9e3e905);
    GG(d, a, b, c, x[2], 9, 0xfcefa3f8);
    GG(c, d, a, b, x[7], 14, 0x676f02d9);
    GG(b, c, d, a, x[12], 20, 0x8d2a4c8a);
    HH(a, b, c, d, x[5], 4, 0xfffa3942);
    HH(d, a, b, c, x[8], 11, 0x8771f681);
    HH(c, d, a, b, x[11], 16, 0x6d9d6122);
    HH(b, c, d, a, x[14], 23, 0xfde5380c);
    HH(a, b, c, d, x[1], 4, 0xa4beea44);
    HH(d, a, b, c, x[4], 11, 0x4bdecfa9);
    HH(c, d, a, b, x[7], 16, 0xf6bb4b60);
    HH(b, c, d, a, x[10], 23, 0xbebfbc70);
    HH(a, b, c, d, x[13], 4, 0x289b7ec6);
    HH(d, a, b, c, x[0], 11, 0xeaa127fa);
    HH(c, d, a, b, x[3], 16, 0xd4ef3085);
    HH(b, c, d, a, x[6], 23, 0x4881d05);
    HH(a, b, c, d, x[9], 4, 0xd9d4d039);
    HH(d, a, b, c, x[12], 11, 0xe6db99e5);
    HH(c, d, a, b, x[15], 16, 0x1fa27cf8);
    HH(b, c, d, a, x[2], 23, 0xc4ac5665);
    II(a, b, c, d, x[0], 6, 0xf4292244);
    II(d, a, b, c, x[7], 10, 0x432aff97);
    II(c, d, a, b, x[14], 15, 0xab9423a7);
    II(b, c, d, a, x[5], 21, 0xfc93a039);
    II(a, b, c, d, x[12], 6, 0x655b59c3);
    II(d, a, b, c, x[3], 10, 0x8f0ccc92);
    II(c, d, a, b, x[10], 15, 0xffeff47d);
    II(b, c, d, a, x[1], 21, 0x85845dd1);
    II(a, b, c, d, x[8], 6, 0x6fa87e4f);
    II(d, a, b, c, x[15], 10, 0xfe2ce6e0);
    II(c, d, a, b, x[6], 15, 0xa3014314);
    II(b, c, d, a, x[13], 21, 0x4e0811a1);
    II(a, b, c, d, x[4], 6, 0xf7537e82);
    II(d, a, b, c, x[11], 10, 0xbd3af235);
    II(c, d, a, b, x[2], 15, 0x2ad7d2bb);
    II(b, c, d, a, x[9], 21, 0xeb86d391);
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    std::memset(x, 0, sizeof(x));
}

HPEHash::HPEMD5 &HPEHash::HPEMD5::update(const unsigned char *input, size_type length)
{
    size_type index = count[0] / 8 % blocksize;
    if ((count[0] += (length << 3)) < (length << 3))
        count[1]++;
    count[1] += (length >> 29);
    size_type firstpart = 64 - index;
    size_type i;
    if (length >= firstpart)
    {
        memcpy(&buffer[index], input, firstpart);
        transform(buffer);
        for (i = firstpart; i + blocksize <= length; i += blocksize)
            transform(&input[i]);
        index = 0;
    }
    else
    {
        i = 0;
    }
    memcpy(&buffer[index], &input[i], length - i);
    return *this;
}

HPEHash::HPEMD5 &HPEHash::HPEMD5::update(const std::string &input)
{
    return update((const unsigned char *)input.c_str(), input.length());
}

std::string HPEHash::HPEMD5::finalHex()
{
    if (!finalized)
    {
        unsigned char padding[64];
        memset(padding, 0, 64);
        padding[0] = 0x80;
        update(padding, (count[0] % 64 < 56) ? (56 - count[0] % 64) : (120 - count[0] % 64));

        unsigned char bits[8];
        encode(bits, count, 8);
        update(bits, 8);

        finalized = true;
    }
    return digestToHex();
}

std::string HPEHash::HPEMD5::digestToHex()
{
    std::stringstream ss;
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)((state[i] >> (j * 8)) & 0xff);
        }
    }
    return ss.str();
}
std::vector<uint8_t> HPEHash::HPEShake256::digest(const std::vector<uint8_t> &input, size_t outputLength)
{
    HPEShake256 ctx;
    ctx.absorb(input);
    return ctx.squeeze(outputLength);
}

std::vector<uint8_t> HPEHash::HPEShake256::digest(const uint8_t *input, size_t inputLen, size_t outputLength)
{
    HPEShake256 ctx;
    ctx.absorb(input, inputLen);
    return ctx.squeeze(outputLength);
}

void HPEHash::HPEShake256::absorb(const std::vector<uint8_t> &input)
{
    absorb(input.data(), input.size());
}

void HPEHash::HPEShake256::absorb(const uint8_t *input, size_t length)
{
    if (finalized)
        throw std::runtime_error("Shake256: Already finalized");
    size_t i = 0;
    if (bufferIndex > 0)
    {
        size_t toFill = std::min(length, KECCAK_RATE - bufferIndex);
        std::memcpy(&buffer[bufferIndex], input, toFill);
        bufferIndex += toFill;
        i += toFill;

        if (bufferIndex == KECCAK_RATE)
        {
            xorBufferIntoState();
            keccakF1600();
            bufferIndex = 0;
        }
    }
    while (i + KECCAK_RATE <= length)
    {
        std::memcpy(buffer, &input[i], KECCAK_RATE);
        xorBufferIntoState();
        keccakF1600();
        i += KECCAK_RATE;
    }
    if (i < length)
    {
        std::memcpy(&buffer[bufferIndex], &input[i], length - i);
        bufferIndex += length - i;
    }
}

std::vector<uint8_t> HPEHash::HPEShake256::squeeze(size_t outputLength)
{
    if (!finalized)
    {
        buffer[bufferIndex] ^= 0x1F;
        buffer[KECCAK_RATE - 1] ^= 0x80;
        xorBufferIntoState();
        keccakF1600();
        finalized = true;
        bufferIndex = 0;
    }
    std::vector<uint8_t> output(outputLength);
    size_t generated = 0;
    while (generated < outputLength)
    {
        size_t toCopy = std::min(outputLength - generated, static_cast<size_t>(KECCAK_RATE));
        for (size_t i = 0; i < toCopy; ++i)
        {
            size_t word_idx = (bufferIndex + i) / 8;
            size_t byte_idx = (bufferIndex + i) % 8;
            uint8_t byte_val = (state[word_idx] >> (byte_idx * 8)) & 0xFF;
            output[generated + i] = byte_val;
        }
        generated += toCopy;
        bufferIndex += toCopy;
        if (bufferIndex >= KECCAK_RATE)
        {
            keccakF1600();
            bufferIndex = 0;
        }
    }
    return output;
}

void HPEHash::HPEShake256::xorBufferIntoState()
{
    for (int i = 0; i < KECCAK_RATE / 8; ++i)
    {
        uint64_t word = 0;
        memcpy(&word, &buffer[i * 8], 8);
        state[i] ^= word;
    }
}

void HPEHash::HPEShake256::keccakF1600()
{
    const uint64_t RC[24] = {
        0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
        0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
        0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
        0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
        0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
        0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
        0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
        0x8000000080008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};
    for (int round = 0; round < 24; ++round)
    {
        uint64_t C[5], D[5];
        uint64_t B[25];
        for (int x = 0; x < 5; ++x)
        {
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for (int x = 0; x < 5; ++x)
        {
            D[x] = C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1);
            for (int y = 0; y < 5; ++y)
            {
                state[x + 5 * y] ^= D[x];
            }
        }
        B[0] = state[0];
        int x = 1, y = 0;
        for (int t = 0; t < 24; ++t)
        {
            static const int rot_offsets[5][5] = {
                {0, 36, 3, 41, 18},
                {1, 44, 10, 45, 2},
                {62, 6, 43, 15, 61},
                {28, 55, 25, 21, 56},
                {27, 20, 39, 8, 14}};
            B[y + 5 * x] = rotl(state[x + 5 * y], rot_offsets[x][y]);
            int new_x = y;
            int new_y = (2 * x + 3 * y) % 5;
            x = new_x;
            y = new_y;
        }
        for (int y = 0; y < 5; ++y)
        {
            for (int x = 0; x < 5; ++x)
            {
                state[x + 5 * y] = B[x + 5 * y] ^ ((~B[((x + 1) % 5) + 5 * y]) & B[((x + 2) % 5) + 5 * y]);
            }
        }
        state[0] ^= RC[round];
    }
}
