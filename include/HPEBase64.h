#pragma once
#include <string>
#include <vector>
#include <random>
#include <stdexcept>

namespace
{
    static const char base64Chars[] = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"    
        "abcdefghijklmnopqrstuvwxyz"                                
        "0123456789+/";
}

namespace HPEBase64
{
    // 编码：字节数组 -> Base64 字符串
    std::string bytesToBase64(const std::vector<uint8_t> &bytes);
    
    // 解码：Base64 字符串 -> 字节数组 (新增)
    std::vector<uint8_t> base64ToBytes(const std::string &encodedString);

    // 生成随机 Base64 字符串
    std::string GenerateRandomBase64FromBytes(int desiredLength);
}

std::string HPEBase64::bytesToBase64(const std::vector<uint8_t> &bytes)
{
    std::string result;
    size_t i = 0;
    while (i < bytes.size())
    {
        uint32_t octet_a = i < bytes.size() ? bytes[i++] : 0;
        uint32_t octet_b = i < bytes.size() ? bytes[i++] : 0;
        uint32_t octet_c = i < bytes.size() ? bytes[i++] : 0;
        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;
        result.push_back(base64Chars[(triple >> 18) & 0x3F]);
        result.push_back(base64Chars[(triple >> 12) & 0x3F]);
        result.push_back(base64Chars[(triple >> 6) & 0x3F]);
        result.push_back(base64Chars[triple & 0x3F]);
    }
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

std::vector<uint8_t> HPEBase64::base64ToBytes(const std::string &encodedString)
{
    std::vector<uint8_t> result;
    int i = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];

    for (char c : encodedString) {
        // 忽略换行符和回车符
        if (c == '\n' || c == '\r') continue;
        
        // 遇到填充符 '=' 或非法字符停止处理数据部分
        if (c == '=') break;

        // 查找字符在 Base64 表中的位置
        const char* pos = strchr(base64Chars, c);
        if (pos == nullptr) continue; // 跳过非法字符
        
        char_array_4[in_] = static_cast<unsigned char>(pos - base64Chars);
        in_++;

        if (in_ == 4) {
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; i < 3; i++)
                result.push_back(char_array_3[i]);
            in_ = 0;
        }
    }

    // 处理剩余不足 4 个字符的情况
    if (in_) {
        for (i = in_; i < 4; i++)
            char_array_4[i] = 0;

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (i = 0; i < in_ - 1; i++)
            result.push_back(char_array_3[i]);
    }

    return result;
}

std::string HPEBase64::GenerateRandomBase64FromBytes(int desired_length)
{
    int bytes_needed = ((desired_length + 3) / 4) * 3;
    std::vector<uint8_t> random_bytes(bytes_needed);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (int i = 0; i < bytes_needed; ++i) random_bytes[i] = static_cast<uint8_t>(dis(gen));
    std::string encoded = HPEBase64::bytesToBase64(random_bytes);
    return encoded.substr(0, desired_length);
}