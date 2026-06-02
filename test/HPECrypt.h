#pragma once
#include <string>
#include <ctime>
#include <cstdio>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <random>
#include <cstdint>
#include <cstring>
#include <chrono>

// ================= 内部实现隐藏区域 =================
namespace {
    // --- MD5 实现 ---
    class MD5Impl {
    public:
        typedef unsigned int size_type; 
        MD5Impl() { init(); }
        MD5Impl& update(const unsigned char* input, size_type length);
        MD5Impl& update(const std::string& input);
        std::string final_hex();
        
    private:
        void init();
        typedef unsigned char uint1; 
        typedef unsigned int uint4;  
        enum {blocksize = 64}; 

        void transform(const uint1 block[blocksize]);
        static void decode(uint4 output[], const uint1 input[], size_type len);
        static void encode(uint1 output[], const uint4 input[], size_type len);

        bool finalized;
        uint1 buffer[blocksize]; 
        uint4 count[2]; 
        uint4 state[4]; 

        std::string digest_to_hex();
        
        static inline uint4 F(uint4 x, uint4 y, uint4 z) { return (x & y) | (~x & z); }
        static inline uint4 G(uint4 x, uint4 y, uint4 z) { return (x & z) | (y & ~z); }
        static inline uint4 H(uint4 x, uint4 y, uint4 z) { return x ^ y ^ z; }
        static inline uint4 I(uint4 x, uint4 y, uint4 z) { return y ^ (x | ~z); }
        static inline uint4 rotate_left(uint4 x, int n) { return (x << n) | (x >> (32-n)); }
        static inline void FF(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) {
            a = rotate_left(a + F(b,c,d) + x + ac, s) + b;
        }
        static inline void GG(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) {
            a = rotate_left(a + G(b,c,d) + x + ac, s) + b;
        }
        static inline void HH(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) {
            a = rotate_left(a + H(b,c,d) + x + ac, s) + b;
        }
        static inline void II(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) {
            a = rotate_left(a + I(b,c,d) + x + ac, s) + b;
        }
    };

    void MD5Impl::init() {
        finalized=false;
        count[0] = 0;
        count[1] = 0;
        state[0] = 0x67452301;
        state[1] = 0xefcdab89;
        state[2] = 0x98badcfe;
        state[3] = 0x10325476;
    }

    void MD5Impl::decode(uint4 output[], const uint1 input[], size_type len) {
        for (unsigned int i = 0, j = 0; j < len; i++, j += 4)
            output[i] = ((uint4)input[j]) | (((uint4)input[j+1]) << 8) |
                        (((uint4)input[j+2]) << 16) | (((uint4)input[j+3]) << 24);
    }

    void MD5Impl::encode(uint1 output[], const uint4 input[], size_type len) {
        for (size_type i = 0, j = 0; j < len; i++, j += 4) {
            output[j] = input[i] & 0xff;
            output[j+1] = (input[i] >> 8) & 0xff;
            output[j+2] = (input[i] >> 16) & 0xff;
            output[j+3] = (input[i] >> 24) & 0xff;
        }
    }

    void MD5Impl::transform(const uint1 block[blocksize]) {
        uint4 a = state[0], b = state[1], c = state[2], d = state[3], x[16];
        decode (x, block, blocksize);

        /* Round 1 */
        FF (a, b, c, d, x[ 0], 7, 0xd76aa478); FF (d, a, b, c, x[ 1], 12, 0xe8c7b756);
        FF (c, d, a, b, x[ 2], 17, 0x242070db); FF (b, c, d, a, x[ 3], 22, 0xc1bdceee);
        FF (a, b, c, d, x[ 4], 7, 0xf57c0faf); FF (d, a, b, c, x[ 5], 12, 0x4787c62a);
        FF (c, d, a, b, x[ 6], 17, 0xa8304613); FF (b, c, d, a, x[ 7], 22, 0xfd469501);
        FF (a, b, c, d, x[ 8], 7, 0x698098d8); FF (d, a, b, c, x[ 9], 12, 0x8b44f7af);
        FF (c, d, a, b, x[10], 17, 0xffff5bb1); FF (b, c, d, a, x[11], 22, 0x895cd7be);
        FF (a, b, c, d, x[12], 7, 0x6b901122); FF (d, a, b, c, x[13], 12, 0xfd987193);
        FF (c, d, a, b, x[14], 17, 0xa679438e); FF (b, c, d, a, x[15], 22, 0x49b40821);

        /* Round 2 */
        GG (a, b, c, d, x[ 1], 5, 0xf61e2562); GG (d, a, b, c, x[ 6], 9, 0xc040b340);
        GG (c, d, a, b, x[11], 14, 0x265e5a51); GG (b, c, d, a, x[ 0], 20, 0xe9b6c7aa);
        GG (a, b, c, d, x[ 5], 5, 0xd62f105d); GG (d, a, b, c, x[10], 9,  0x2441453);
        GG (c, d, a, b, x[15], 14, 0xd8a1e681); GG (b, c, d, a, x[ 4], 20, 0xe7d3fbc8);
        GG (a, b, c, d, x[ 9], 5, 0x21e1cde6); GG (d, a, b, c, x[14], 9, 0xc33707d6);
        GG (c, d, a, b, x[ 3], 14, 0xf4d50d87); GG (b, c, d, a, x[ 8], 20, 0x455a14ed);
        GG (a, b, c, d, x[13], 5, 0xa9e3e905); GG (d, a, b, c, x[ 2], 9, 0xfcefa3f8);
        GG (c, d, a, b, x[ 7], 14, 0x676f02d9); GG (b, c, d, a, x[12], 20, 0x8d2a4c8a);

        /* Round 3 */
        HH (a, b, c, d, x[ 5], 4, 0xfffa3942); HH (d, a, b, c, x[ 8], 11, 0x8771f681);
        HH (c, d, a, b, x[11], 16, 0x6d9d6122); HH (b, c, d, a, x[14], 23, 0xfde5380c);
        HH (a, b, c, d, x[ 1], 4, 0xa4beea44); HH (d, a, b, c, x[ 4], 11, 0x4bdecfa9);
        HH (c, d, a, b, x[ 7], 16, 0xf6bb4b60); HH (b, c, d, a, x[10], 23, 0xbebfbc70);
        HH (a, b, c, d, x[13], 4, 0x289b7ec6); HH (d, a, b, c, x[ 0], 11, 0xeaa127fa);
        HH (c, d, a, b, x[ 3], 16, 0xd4ef3085); HH (b, c, d, a, x[ 6], 23,  0x4881d05);
        HH (a, b, c, d, x[ 9], 4, 0xd9d4d039); HH (d, a, b, c, x[12], 11, 0xe6db99e5);
        HH (c, d, a, b, x[15], 16, 0x1fa27cf8); HH (b, c, d, a, x[ 2], 23, 0xc4ac5665);

        /* Round 4 */
        II (a, b, c, d, x[ 0], 6, 0xf4292244); II (d, a, b, c, x[ 7], 10, 0x432aff97);
        II (c, d, a, b, x[14], 15, 0xab9423a7); II (b, c, d, a, x[ 5], 21, 0xfc93a039);
        II (a, b, c, d, x[12], 6, 0x655b59c3); II (d, a, b, c, x[ 3], 10, 0x8f0ccc92);
        II (c, d, a, b, x[10], 15, 0xffeff47d); II (b, c, d, a, x[ 1], 21, 0x85845dd1);
        II (a, b, c, d, x[ 8], 6, 0x6fa87e4f); II (d, a, b, c, x[15], 10, 0xfe2ce6e0);
        II (c, d, a, b, x[ 6], 15, 0xa3014314); II (b, c, d, a, x[13], 21, 0x4e0811a1);
        II (a, b, c, d, x[ 4], 6, 0xf7537e82); II (d, a, b, c, x[11], 10, 0xbd3af235);
        II (c, d, a, b, x[ 2], 15, 0x2ad7d2bb); II (b, c, d, a, x[ 9], 21, 0xeb86d391);

        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        memset(x, 0, sizeof(x));
    }

    MD5Impl& MD5Impl::update(const unsigned char* input, size_type length) {
        size_type index = count[0] / 8 % blocksize;
        if ((count[0] += (length << 3)) < (length << 3)) count[1]++;
        count[1] += (length >> 29);
        size_type firstpart = 64 - index;
        size_type i;
        if (length >= firstpart) {
            memcpy(&buffer[index], input, firstpart);
            transform(buffer);
            for (i = firstpart; i + blocksize <= length; i += blocksize)
                transform(&input[i]);
            index = 0;
        } else {
            i = 0;
        }
        memcpy(&buffer[index], &input[i], length-i);
        return *this;
    }

    MD5Impl& MD5Impl::update(const std::string& input) {
        return update((const unsigned char*)input.c_str(), input.length());
    }

    std::string MD5Impl::final_hex() {
        if (!finalized) {
            unsigned char padding[64];
            memset(padding, 0, 64);
            padding[0] = 0x80;
            update(padding, (count[0] % 64 < 56) ? (56 - count[0] % 64) : (120 - count[0] % 64));
            unsigned char bits[8];
            encode(bits, count, 8);
            update(bits, 8);
            finalized = true;
        }
        return digest_to_hex();
    }

    std::string MD5Impl::digest_to_hex() {
        std::stringstream ss;
        for(int i=0; i<4; i++) {
            for(int j=0; j<4; j++) {
                ss << std::hex << std::setw(2) << std::setfill('0') << (int)((state[i] >> (j*8)) & 0xff);
            }
        }
        return ss.str();
    }

    // --- Base64 实现 ---
    static const char base64_chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string bytes_to_base64(const std::vector<uint8_t> &bytes) {
        std::string result;
        size_t i = 0;
        while (i < bytes.size()) {
            uint32_t octet_a = i < bytes.size() ? bytes[i++] : 0;
            uint32_t octet_b = i < bytes.size() ? bytes[i++] : 0;
            uint32_t octet_c = i < bytes.size() ? bytes[i++] : 0;
            uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;
            result.push_back(base64_chars[(triple >> 18) & 0x3F]);
            result.push_back(base64_chars[(triple >> 12) & 0x3F]);
            result.push_back(base64_chars[(triple >> 6) & 0x3F]);
            result.push_back(base64_chars[triple & 0x3F]);
        }
        size_t mod = bytes.size() % 3;
        if (mod == 1) {
            result.pop_back(); result.pop_back();
            result.push_back('='); result.push_back('=');
        } else if (mod == 2) {
            result.pop_back();
            result.push_back('=');
        }
        return result;
    }

    std::string GenerateRandomBase64FromBytes(int desired_length) {
        int bytes_needed = ((desired_length + 3) / 4) * 3;
        std::vector<uint8_t> random_bytes(bytes_needed);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        for (int i = 0; i < bytes_needed; ++i) {
            random_bytes[i] = static_cast<uint8_t>(dis(gen));
        }
        std::string encoded = bytes_to_base64(random_bytes);
        return encoded.substr(0, desired_length);
    }

    std::string ComputeMD5(const std::string &text) {
        MD5Impl md5;
        md5.update(text);
        return md5.final_hex();
    }
} // namespace anonymous

// ================= 公开接口区域 =================
namespace HPECrypt
{
    /**
     * @brief 生成新的 Key 和 UKey 文件
     * @param KPath key.key 文件路径
     * @param UKPath key.ukey 文件路径
     * @return 生成的 Base64 编码的 Key 字符串
     */
    std::string NewKey(const std::string &KPath = "key.key", const std::string &UKPath = "key.ukey")
    {
        // 1. 获取当前时间戳Token (秒级)
        time_t now = time(nullptr);
        long long timeToken = static_cast<long long>(now);

        // 2. 获取6位随机数Token (微秒部分取模)
        // 注意：time_t 精度通常为秒，若需高精度微秒，需使用 chrono
        auto now_chrono = std::chrono::system_clock::now();
        auto duration = now_chrono.time_since_epoch();
        auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(duration).count();
        int randomNum = static_cast<int>(microseconds % 1000000);
        if (randomNum < 0) randomNum += 1000000;

        // 3. 获取12位随机base64字符串Token
        std::string base64Token = GenerateRandomBase64FromBytes(12);

        // 4. 计算 MD5 Token
        std::string temp = std::to_string(timeToken) + std::to_string(randomNum) + base64Token;
        std::string strtoken = ComputeMD5(temp);

        // 5. 计算 Final Key
        std::string keyT = temp + strtoken;
        std::string key = ComputeMD5(keyT);

        // 打印调试信息 (可选)
        printf("TimeToken: %lld\n", timeToken);
        printf("RandomNum: %d\n", randomNum);
        printf("Base64Token: %s\n", base64Token.c_str());
        printf("StrToken: %s\n", strtoken.c_str());
        printf("Key: %s\n", key.c_str());

        // 6. 生成 Key 文件内容
        std::string rawKeyData = std::to_string(timeToken) + std::to_string(randomNum) + base64Token + strtoken + key;
        
        // Base64 编码
        std::vector<uint8_t> keyBytes(rawKeyData.begin(), rawKeyData.end());
        std::string base64KeyData = bytes_to_base64(keyBytes);

        // 写入 Key 文件
        std::ofstream keyFile(KPath);
        if (keyFile.is_open()) {
            keyFile << base64KeyData;
            keyFile << "\ntype:key";
            keyFile.close();
        }

        // 7. 生成 UKey 文件内容 (字节交换)
        std::vector<uint8_t> ukeyData(rawKeyData.begin(), rawKeyData.end());
        std::vector<uint8_t> out;
        for (size_t i = 0; i < ukeyData.size(); i += 2) {
            if (i + 1 < ukeyData.size()) {
                out.push_back(ukeyData[i+1]);
                out.push_back(ukeyData[i]);
            } else {
                out.push_back(ukeyData[i]);
            }
        }

        // 写入 UKey 文件
        std::ofstream ukeyFile(UKPath, std::ios::binary);
        if (ukeyFile.is_open()) {
            ukeyFile.write(reinterpret_cast<const char*>(out.data()), out.size());
            ukeyFile << "\ntype:Ukey";
            ukeyFile.close();
        }

        return base64KeyData;
    }

    /**
     * @brief 加密明文
     * @param PlainText 待加密字符串
     * @param UKPath UKey 文件路径
     * @return 加密后的字符串 (Base64编码)
     */
    std::string encrypt(const std::string &PlainText, const std::string &UKPath = "key.ukey")
    {
        // TODO: 实现加密逻辑
        // 1. 读取 UKey 文件
        // 2. 解析 UKey (反转字节交换)
        // 3. 提取密钥材料
        // 4. 使用密钥对 PlainText 进行加密 (例如 AES/XOR)
        // 5. 返回 Base64 编码的密文
        return "";
    }

    /**
     * @brief 解密密文
     * @param CipherText 待解密字符串 (Base64编码)
     * @param KPath Key 文件路径
     * @return 解密后的明文字符串
     */
    std::string decrypt(const std::string &CipherText, const std::string &KPath = "key.key")
    {
        // TODO: 实现解密逻辑
        // 1. 读取 Key 文件
        // 2. 解析 Key (Base64解码)
        // 3. 提取密钥材料
        // 4. 对 CipherText 进行 Base64 解码
        // 5. 使用密钥对密文进行解密
        // 6. 返回明文
        return "";
    }
}