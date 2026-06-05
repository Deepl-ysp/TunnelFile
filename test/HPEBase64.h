#pragma once
#include <string>
#include <cstring>
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
    std::string bytesToBase64(const std::vector<uint8_t> &bytes);

    std::vector<uint8_t> base64ToBytes(const std::string &encodedString);

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
    if (mod == 1)
    {
        result.pop_back();
        result.pop_back();
        result.push_back('=');
        result.push_back('=');
    }
    else if (mod == 2)
    {
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

    for (char c : encodedString)
    {
        if (c == '\n' || c == '\r')
            continue;
        if (c == '=')
            break;
        const char *pos = strchr(base64Chars, c);
        if (pos == nullptr)
            continue;
        char_array_4[in_] = static_cast<unsigned char>(pos - base64Chars);
        in_++;
        if (in_ == 4)
        {
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
            for (i = 0; i < 3; i++)
                result.push_back(char_array_3[i]);
            in_ = 0;
        }
    }
    if (in_)
    {
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
    for (int i = 0; i < bytes_needed; ++i)
        random_bytes[i] = static_cast<uint8_t>(dis(gen));
    std::string encoded = HPEBase64::bytesToBase64(random_bytes);
    return encoded.substr(0, desired_length);
}