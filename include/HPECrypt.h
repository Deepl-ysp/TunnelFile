#pragma once
#include <fstream>
#include <vector>
#include <iostream>
#include <chrono>
#include <random>
#include "HPEHash.h"
#include "HPEBase64.h"

// !!! 安全警告 !!!
// 此文件中的加解密实现仅供开发者学习 HPE 协议使用。
// 公开的密钥和固定算法极易被逆向，请勿直接用于任何实际项目。
// 正式环境中必须自行实现安全强度足够的加解密方案。
namespace HPECrypt
{
    std::vector<uint8_t> loadPrivateKeyFromFile(const std::string &path)
    {
        std::ifstream ifs(path);
        if (!ifs.is_open())
            throw std::runtime_error("Cannot open key file: " + path);
        std::string line;
        if (std::getline(ifs, line))
        {
            if (!line.empty() && line.back() == '\r')
                line.pop_back();
            return HPEBase64::base64ToBytes(line);
        }
        throw std::runtime_error("Key file is empty");
    }

    std::vector<uint8_t> loadPublicKeyFromFile(const std::string &path)
    {
        std::ifstream ifs(path, std::ios::binary | std::ios::ate);
        if (!ifs.is_open())
            throw std::runtime_error("Cannot open ukey file: " + path);
        std::streamsize size = ifs.tellg();
        ifs.seekg(0, std::ios::beg);
        std::vector<char> buffer(size);
        if (ifs.read(buffer.data(), size))
        {
            std::string content(buffer.begin(), buffer.end());
            std::string marker1 = "\ntype:Ukey";
            std::string marker2 = "\r\ntype:Ukey";
            size_t pos = std::string::npos;
            if (content.find(marker1) != std::string::npos)
                pos = content.rfind(marker1);
            else if (content.find(marker2) != std::string::npos)
                pos = content.rfind(marker2);
            else
                throw std::runtime_error("Invalid Ukey file: missing type marker");
            std::string reversed_data = content.substr(0, pos);
            if (!reversed_data.empty() && reversed_data.back() == '\r')
                reversed_data.pop_back();
            std::vector<uint8_t> raw(reversed_data.begin(), reversed_data.end());
            std::vector<uint8_t> restored;
            for (size_t i = 0; i < raw.size(); i += 2)
            {
                if (i + 1 < raw.size())
                {
                    restored.push_back(raw[i + 1]);
                    restored.push_back(raw[i]);
                }
                else
                    restored.push_back(raw[i]);
            }
            return restored;
        }
        throw std::runtime_error("Failed to read Ukey file");
    }

    std::string encryptTextWithKeyMaterial(const std::string &plaintext, const std::vector<uint8_t> &pubKeyMaterial)
    {
        try
        {
            std::vector<uint8_t> seedMaterial = pubKeyMaterial;
            std::string saltStr = generateDigitString(12);
            std::vector<uint8_t> salt(saltStr.begin(), saltStr.end());
            std::vector<uint8_t> streamSeed(seedMaterial.begin(), seedMaterial.end());
            streamSeed.insert(streamSeed.end(), salt.begin(), salt.end());
            std::vector<uint8_t> key_stream = HPEHash::HPEShake256::digest(streamSeed, plaintext.size());
            std::vector<uint8_t> ciphertext(plaintext.size());
            for (size_t i = 0; i < plaintext.size(); ++i)
                ciphertext[i] = static_cast<uint8_t>(plaintext[i]) ^ key_stream[i];
            std::vector<uint8_t> result;
            result.reserve(salt.size() + ciphertext.size());
            result.insert(result.end(), salt.begin(), salt.end());
            result.insert(result.end(), ciphertext.begin(), ciphertext.end());
            return std::string(result.begin(), result.end());
        }
        catch (const std::exception &e)
        {
            std::cerr << "Encryption error: " << e.what() << std::endl;
            return "";
        }
    }

    std::string decryptTextWithKeyMaterial(const std::string &ciphertext, const std::vector<uint8_t> &privKeyMaterial)
    {
        if (ciphertext.size() < 12)
        {
            throw std::invalid_argument("Ciphertext too short to contain salt");
        }
        std::vector<uint8_t> salt(ciphertext.begin(), ciphertext.begin() + 12);
        std::vector<uint8_t> encryptedData(ciphertext.begin() + 12, ciphertext.end());
        std::vector<uint8_t> seedMaterial = privKeyMaterial;
        std::vector<uint8_t> streamSeed;
        streamSeed.reserve(seedMaterial.size() + salt.size());
        streamSeed.insert(streamSeed.end(), seedMaterial.begin(), seedMaterial.end());
        streamSeed.insert(streamSeed.end(), salt.begin(), salt.end());
        size_t KeyStreamLength = encryptedData.size();
        std::vector<uint8_t> keyStream = HPEHash::HPEShake256::digest(streamSeed, KeyStreamLength);
        std::vector<uint8_t> plaintext(KeyStreamLength);
        for (size_t i = 0; i < KeyStreamLength; ++i)
            plaintext[i] = static_cast<uint8_t>(encryptedData[i]) ^ keyStream[i];
        return std::string(plaintext.begin(), plaintext.end());
    }

    std::string NewKey(const std::string &KPath = "key.key", const std::string &UKPath = "Ukey.key")
    {
        auto now = std::chrono::system_clock::now();
        auto time_t_now = std::chrono::system_clock::to_time_t(now);
        long long timeToken = static_cast<long long>(time_t_now);
        auto duration = now.time_since_epoch();
        auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(duration).count();
        int randomNum = static_cast<int>(microseconds % 1000000);
        if (randomNum < 0)
            randomNum += 1000000;
        std::string base64Token = HPEBase64::GenerateRandomBase64FromBytes(12);
        auto MD5Hash = [](const std::string &text) -> std::string
        {
            HPEHash::HPEMD5 md5;
            md5.update(text);
            return md5.finalHex();
        };
        std::string temp = std::to_string(timeToken) + std::to_string(randomNum) + base64Token;
        std::string strtoken = MD5Hash(temp);
        std::string keyT = temp + strtoken;
        std::string key = MD5Hash(keyT);
        std::string rawKeyData = std::to_string(timeToken) + std::to_string(randomNum) + base64Token + strtoken + key;
        std::vector<uint8_t> keyBytes(rawKeyData.begin(), rawKeyData.end());
        std::string base64KeyData = HPEBase64::bytesToBase64(keyBytes);
        std::ofstream keyFile(KPath);
        if (keyFile.is_open())
        {
            keyFile << base64KeyData;
            keyFile << "\ntype:key";
            keyFile.close();
        }
        std::vector<uint8_t> ukeyData(rawKeyData.begin(), rawKeyData.end());
        std::vector<uint8_t> out;
        for (size_t i = 0; i < ukeyData.size(); i += 2)
        {
            if (i + 1 < ukeyData.size())
            {
                out.push_back(ukeyData[i + 1]);
                out.push_back(ukeyData[i]);
            }
            else
                out.push_back(ukeyData[i]);
        }
        std::ofstream ukeyFile(UKPath, std::ios::binary);
        if (ukeyFile.is_open())
        {
            ukeyFile.write(reinterpret_cast<const char *>(out.data()), out.size());
            ukeyFile << "\ntype:Ukey";
            ukeyFile.close();
        }
        return base64KeyData;
    }

}

namespace
{
    std::string generateDigitString(int length = 12)
    {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 9);
        std::string result;
        result.reserve(length);
        for (int i = 0; i < length; ++i)
            result.push_back('0' + dis(gen));
        return result;
    }
}