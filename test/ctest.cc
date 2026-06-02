#include <iostream>
#include <string>
#include <cstring>
#include <random>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <fstream>
#include <cstdint>
#include <ctime>

// ================= MD5 实现开始 =================
// 为了无需外部依赖，这里内嵌一个标准的 MD5 实现
class MD5 {
public:
    typedef unsigned int size_type; // must be 32bit

    MD5();
    MD5& update(const unsigned char* input, size_type length);
    MD5& update(const std::string& input);
    std::string final_hex();
    
private:
    void init();
    typedef unsigned char uint1; //  8bit
    typedef unsigned int uint4;  // 32bit
    enum {blocksize = 64}; // VC6 won't eat a const static int here

    void transform(const uint1 block[blocksize]);
    static void decode(uint4 output[], const uint1 input[], size_type len);
    static void encode(uint1 output[], const uint4 input[], size_type len);

    bool finalized;
    uint1 buffer[blocksize]; // bytes that didn't make it to the transform
    uint4 count[2]; // number of bits, modulo 2^64 (lsb first)
    uint4 state[4]; // digest buffer

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

MD5::MD5() { init(); }

void MD5::init() {
    finalized=false;
    count[0] = 0;
    count[1] = 0;
    // load magic initialization constants.
    state[0] = 0x67452301;
    state[1] = 0xefcdab89;
    state[2] = 0x98badcfe;
    state[3] = 0x10325476;
}

// Decodes input (unsigned char) into output (uint4). Assumes len is a multiple of 4.
void MD5::decode(uint4 output[], const uint1 input[], size_type len) {
    for (unsigned int i = 0, j = 0; j < len; i++, j += 4)
        output[i] = ((uint4)input[j]) | (((uint4)input[j+1]) << 8) |
                    (((uint4)input[j+2]) << 16) | (((uint4)input[j+3]) << 24);
}

// Encodes input (uint4) into output (unsigned char). Assumes len is a multiple of 4.
void MD5::encode(uint1 output[], const uint4 input[], size_type len) {
    for (size_type i = 0, j = 0; j < len; i++, j += 4) {
        output[j] = input[i] & 0xff;
        output[j+1] = (input[i] >> 8) & 0xff;
        output[j+2] = (input[i] >> 16) & 0xff;
        output[j+3] = (input[i] >> 24) & 0xff;
    }
}

// Apply MD5 transformation to a block
void MD5::transform(const uint1 block[blocksize]) {
    uint4 a = state[0], b = state[1], c = state[2], d = state[3], x[16];
    decode (x, block, blocksize);

    /* Round 1 */
    FF (a, b, c, d, x[ 0], 7, 0xd76aa478); /* 1 */
    FF (d, a, b, c, x[ 1], 12, 0xe8c7b756); /* 2 */
    FF (c, d, a, b, x[ 2], 17, 0x242070db); /* 3 */
    FF (b, c, d, a, x[ 3], 22, 0xc1bdceee); /* 4 */
    FF (a, b, c, d, x[ 4], 7, 0xf57c0faf); /* 5 */
    FF (d, a, b, c, x[ 5], 12, 0x4787c62a); /* 6 */
    FF (c, d, a, b, x[ 6], 17, 0xa8304613); /* 7 */
    FF (b, c, d, a, x[ 7], 22, 0xfd469501); /* 8 */
    FF (a, b, c, d, x[ 8], 7, 0x698098d8); /* 9 */
    FF (d, a, b, c, x[ 9], 12, 0x8b44f7af); /* 10 */
    FF (c, d, a, b, x[10], 17, 0xffff5bb1); /* 11 */
    FF (b, c, d, a, x[11], 22, 0x895cd7be); /* 12 */
    FF (a, b, c, d, x[12], 7, 0x6b901122); /* 13 */
    FF (d, a, b, c, x[13], 12, 0xfd987193); /* 14 */
    FF (c, d, a, b, x[14], 17, 0xa679438e); /* 15 */
    FF (b, c, d, a, x[15], 22, 0x49b40821); /* 16 */

    /* Round 2 */
    GG (a, b, c, d, x[ 1], 5, 0xf61e2562); /* 17 */
    GG (d, a, b, c, x[ 6], 9, 0xc040b340); /* 18 */
    GG (c, d, a, b, x[11], 14, 0x265e5a51); /* 19 */
    GG (b, c, d, a, x[ 0], 20, 0xe9b6c7aa); /* 20 */
    GG (a, b, c, d, x[ 5], 5, 0xd62f105d); /* 21 */
    GG (d, a, b, c, x[10], 9,  0x2441453); /* 22 */
    GG (c, d, a, b, x[15], 14, 0xd8a1e681); /* 23 */
    GG (b, c, d, a, x[ 4], 20, 0xe7d3fbc8); /* 24 */
    GG (a, b, c, d, x[ 9], 5, 0x21e1cde6); /* 25 */
    GG (d, a, b, c, x[14], 9, 0xc33707d6); /* 26 */
    GG (c, d, a, b, x[ 3], 14, 0xf4d50d87); /* 27 */
    GG (b, c, d, a, x[ 8], 20, 0x455a14ed); /* 28 */
    GG (a, b, c, d, x[13], 5, 0xa9e3e905); /* 29 */
    GG (d, a, b, c, x[ 2], 9, 0xfcefa3f8); /* 30 */
    GG (c, d, a, b, x[ 7], 14, 0x676f02d9); /* 31 */
    GG (b, c, d, a, x[12], 20, 0x8d2a4c8a); /* 32 */

    /* Round 3 */
    HH (a, b, c, d, x[ 5], 4, 0xfffa3942); /* 33 */
    HH (d, a, b, c, x[ 8], 11, 0x8771f681); /* 34 */
    HH (c, d, a, b, x[11], 16, 0x6d9d6122); /* 35 */
    HH (b, c, d, a, x[14], 23, 0xfde5380c); /* 36 */
    HH (a, b, c, d, x[ 1], 4, 0xa4beea44); /* 37 */
    HH (d, a, b, c, x[ 4], 11, 0x4bdecfa9); /* 38 */
    HH (c, d, a, b, x[ 7], 16, 0xf6bb4b60); /* 39 */
    HH (b, c, d, a, x[10], 23, 0xbebfbc70); /* 40 */
    HH (a, b, c, d, x[13], 4, 0x289b7ec6); /* 41 */
    HH (d, a, b, c, x[ 0], 11, 0xeaa127fa); /* 42 */
    HH (c, d, a, b, x[ 3], 16, 0xd4ef3085); /* 43 */
    HH (b, c, d, a, x[ 6], 23,  0x4881d05); /* 44 */
    HH (a, b, c, d, x[ 9], 4, 0xd9d4d039); /* 45 */
    HH (d, a, b, c, x[12], 11, 0xe6db99e5); /* 46 */
    HH (c, d, a, b, x[15], 16, 0x1fa27cf8); /* 47 */
    HH (b, c, d, a, x[ 2], 23, 0xc4ac5665); /* 48 */

    /* Round 4 */
    II (a, b, c, d, x[ 0], 6, 0xf4292244); /* 49 */
    II (d, a, b, c, x[ 7], 10, 0x432aff97); /* 50 */
    II (c, d, a, b, x[14], 15, 0xab9423a7); /* 51 */
    II (b, c, d, a, x[ 5], 21, 0xfc93a039); /* 52 */
    II (a, b, c, d, x[12], 6, 0x655b59c3); /* 53 */
    II (d, a, b, c, x[ 3], 10, 0x8f0ccc92); /* 54 */
    II (c, d, a, b, x[10], 15, 0xffeff47d); /* 55 */
    II (b, c, d, a, x[ 1], 21, 0x85845dd1); /* 56 */
    II (a, b, c, d, x[ 8], 6, 0x6fa87e4f); /* 57 */
    II (d, a, b, c, x[15], 10, 0xfe2ce6e0); /* 58 */
    II (c, d, a, b, x[ 6], 15, 0xa3014314); /* 59 */
    II (b, c, d, a, x[13], 21, 0x4e0811a1); /* 60 */
    II (a, b, c, d, x[ 4], 6, 0xf7537e82); /* 61 */
    II (d, a, b, c, x[11], 10, 0xbd3af235); /* 62 */
    II (c, d, a, b, x[ 2], 15, 0x2ad7d2bb); /* 63 */
    II (b, c, d, a, x[ 9], 21, 0xeb86d391); /* 64 */

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    memset(x, 0, sizeof(x));
}

MD5& MD5::update(const unsigned char* input, size_type length) {
    // compute number of bytes mod 64
    size_type index = count[0] / 8 % blocksize;
    // update number of bits
    if ((count[0] += (length << 3)) < (length << 3))
        count[1]++;
    count[1] += (length >> 29);
    // number of bytes we need to fill in buffer
    size_type firstpart = 64 - index;
    size_type i;
    // transform as many times as possible.
    if (length >= firstpart) {
        // fill buffer first, transform
        memcpy(&buffer[index], input, firstpart);
        transform(buffer);
        // transform chunks of blocksize (64 bytes)
        for (i = firstpart; i + blocksize <= length; i += blocksize)
            transform(&input[i]);
        index = 0;
    } else {
        i = 0;
    }
    // buffer remaining input
    memcpy(&buffer[index], &input[i], length-i);
    return *this;
}

MD5& MD5::update(const std::string& input) {
    return update((const unsigned char*)input.c_str(), input.length());
}

std::string MD5::final_hex() {
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

std::string MD5::digest_to_hex() {
    std::stringstream ss;
    for(int i=0; i<4; i++) {
        for(int j=0; j<4; j++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)((state[i] >> (j*8)) & 0xff);
        }
    }
    return ss.str();
}
// ================= MD5 实现结束 =================

// Base64编码表
static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

std::string bytes_to_base64(const std::vector<uint8_t> &bytes)
{
    std::string result;
    size_t i = 0;
    while (i < bytes.size())
    {
        uint32_t octet_a = i < bytes.size() ? bytes[i++] : 0;
        uint32_t octet_b = i < bytes.size() ? bytes[i++] : 0;
        uint32_t octet_c = i < bytes.size() ? bytes[i++] : 0;
        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;
        result.push_back(base64_chars[(triple >> 18) & 0x3F]);
        result.push_back(base64_chars[(triple >> 12) & 0x3F]);
        result.push_back(base64_chars[(triple >> 6) & 0x3F]);
        result.push_back(base64_chars[triple & 0x3F]);
    }
    // 移除末尾的 '=' 以匹配 Python 的 [:length] 截取逻辑前的原始行为，
    // 但注意 Python 代码是先 encode 再切片。
    // 这里的 bytes_to_base64 应该返回带 padding 或不带 padding 取决于调用者。
    // 在 GenerateRandomBase64FromBytes 中，我们会截取字符串，所以 padding 不影响前缀。
    // 为了安全起见，我们保留标准 base64 输出，由调用者处理截取。
    // 如果长度不是3的倍数，标准base64会补=。
    size_t mod = bytes.size() % 3;
    if (mod == 1) {
        result.pop_back();
        result.pop_back();
        result.push_back('=');
        result.push_back('=');
    } else if (mod == 2) {
        result.pop_back();
        result.push_back('=');
    }
    return result;
}

std::string GenerateRandomBase64FromBytes(int desired_length)
{
    // Python: num_bytes = ((length + 3) // 4) * 3
    int bytes_needed = ((desired_length + 3) / 4) * 3;
    std::vector<uint8_t> random_bytes(bytes_needed);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (int i = 0; i < bytes_needed; ++i)
    {
        random_bytes[i] = static_cast<uint8_t>(dis(gen));
    }

    std::string encoded = bytes_to_base64(random_bytes);
    // Python: token = base64.b64encode(random_bytes).decode('utf-8')[:length]
    return encoded.substr(0, desired_length);
}

std::string MD5Hash(const std::string &text)
{
    MD5 md5;
    md5.update(text);
    return md5.final_hex();
}

std::string NewKey(const std::string &KPath = "key.key", const std::string &UKPath = "Ukey.key")
{
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    long long timeToken = static_cast<long long>(time_t_now);
    auto duration = now.time_since_epoch();
    auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(duration).count();
    int randomNum = static_cast<int>(microseconds % 1000000);
    if (randomNum < 0) randomNum += 1000000;
    std::string base64Token = GenerateRandomBase64FromBytes(12);
    std::string temp = std::to_string(timeToken) + std::to_string(randomNum) + base64Token;
    std::string strtoken = MD5Hash(temp);
    std::string keyT = temp + strtoken;
    std::string key = MD5Hash(keyT);
    printf("时间戳Token: %lld\n", timeToken);
    printf("随机数Token: %d\n", randomNum);
    printf("Base64 Token: %s\n", base64Token.c_str());
    printf("MD5 Token (strtoken): %s\n", strtoken.c_str());
    printf("Final Key (key): %s\n", key.c_str());
    std::string rawKeyData = std::to_string(timeToken) + std::to_string(randomNum) + base64Token + strtoken + key;
    std::vector<uint8_t> keyBytes(rawKeyData.begin(), rawKeyData.end());
    std::string base64KeyData = bytes_to_base64(keyBytes);
    std::ofstream keyFile(KPath);
    if (keyFile.is_open()) {
        keyFile << base64KeyData;
        keyFile << "\ntype:key";
        keyFile.close();
        std::cout << "Key file written to: " << KPath << std::endl;
    } else {
        std::cerr << "Unable to open file: " << KPath << std::endl;
    }
    std::vector<uint8_t> ukeyData(rawKeyData.begin(), rawKeyData.end());
    std::vector<uint8_t> out;
    for (size_t i = 0; i < ukeyData.size(); i += 2) {
        if (i + 1 < ukeyData.size()) {
            // Swap two bytes
            out.push_back(ukeyData[i+1]);
            out.push_back(ukeyData[i]);
        } else {
            out.push_back(ukeyData[i]);
        }
    }
    std::ofstream ukeyFile(UKPath, std::ios::binary);
    if (ukeyFile.is_open()) {
        ukeyFile.write(reinterpret_cast<const char*>(out.data()), out.size());
        ukeyFile << "\ntype:Ukey";
        ukeyFile.close();
        std::cout << "UKey file written to: " << UKPath << std::endl;
    } else {
        std::cerr << "Unable to open file: " << UKPath << std::endl;
    }
    return base64KeyData;
}

int main()
{
    NewKey();
}