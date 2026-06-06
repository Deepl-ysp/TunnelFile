#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <fstream>
#include <chrono>

namespace
{
    struct Signature
    {
        const char *magic;
        size_t length;
        const char *mime;
    };

    static const Signature kSignatures[] = {
        {"\x89\x50\x4E\x47", 4, "image/png"},
        {"\xFF\xD8\xFF\xE0", 4, "image/jpeg"},
        {"\xFF\xD8\xFF\xE1", 4, "image/jpeg"},
        {"\x47\x49\x46\x38", 4, "image/gif"},
        {"\x42\x4D", 2, "image/bmp"},
        {"\x49\x49\x2A\x00", 4, "image/tiff"},
        {"\x4D\x4D\x00\x2A", 4, "image/tiff"},
        {"\x50\x4B\x03\x04", 4, "application/zip"},
        {"\x52\x61\x72\x21", 4, "application/x-rar-compressed"},
        {"\x37\x7A\xBC\xAF", 4, "application/x-7z-compressed"},
        {"\x25\x50\x44\x46\x2D", 5, "application/pdf"},
        {"\x53\x51\x4C\x69\x74\x65\x20\x66\x6F\x72\x6D\x61\x74\x33\x00", 15, "application/x-sqlite3"},
        {"\x3C\x3F\x78\x6D\x6C", 5, "application/xml"},
        {"\x3C\x68\x74\x6D\x6C", 5, "text/html"},
        {"\x4D\x5A", 2, "application/x-msdownload"},
        {"\x7F\x45\x4C\x46", 4, "application/x-elf"},
        {"\xCA\xFE\xBA\xBE", 4, "application/java-vm"},
        {"\x49\x44\x33", 3, "audio/mpeg"},
        {"\x52\x49\x46\x46", 4, nullptr},
        {"\xD4\xC3\xB2\xA1", 4, "application/vnd.tcpdump.pcap"},
        {"\x4D\x3C\xB2\xA1", 4, "application/vnd.tcpdump.pcap"},
    };
    static bool startsWith(const std::vector<uint8_t> &data, const Signature &sig)
    {
        if (data.size() < sig.length)
            return false;
        return std::memcmp(data.data(), sig.magic, sig.length) == 0;
    }
}

/**
 ## HPEFileAPI 专为HPE项目设计的文件API实现 / HPEFileAPI: A File API Implementation for HPE Project
 - 所属项目 / Associated Project ：HPE (High-Performance Encryption) / HPEHash / TunnelFile
 - 项目链接/Project Link ：https://github.com/Deepl-ysp/TunnelFile/tree/main/include
 - 版本 / Version：1.0
 - 作者 / Author ：Deepl-ysp (GitHub:https://github.com/Deepl-ysp)
 - 创建时间 / Create Time：2026-06-05
 - 最近更新 / Last Update：2026-06-05
 - 许可证 / License：MIT License
 - 使用示例 / Usage Example：
 ```c++
 std::string path = "file.jpg";
 std::vector<uint8_t> vectorData = HPEFileAPI::readFileToUint8Vector(path);
 std::string mimeType = HPEFileAPI::FileMimeType(vectorData);
 HPEFileAPI::FileObject data = HPEFileAPI::readFile(path);
 HPEFileAPI::BlockFileObject blockData = HPEFileAPI::blockFile(data, 1024);
 ```
 */
namespace HPEFileAPI
{

    /**
     ### FileObject 文件对象用于描述一个文件
     - 参数:
     ```c++
        unsigned long long id;      // 文件ID
        std::string name;           // 文件名
        std::string path;           // 文件路径
        std::string suffix;         // 文件后缀
        unsigned long long size;    // 文件大小
        std::string fileType;       // 文件类型
        std::vector<uint8_t> data;  // 文件数据
     ```
     */
    struct FileObject
    {
        unsigned long long id;
        std::string name;
        std::string path;
        std::string suffix;
        unsigned long long size;
        std::string fileType;
        std::vector<uint8_t> data;
    };

    /**
     ### FileBlock 文件块对象
     - 参数:
     ```c++
        unsigned long long fileId;  // 文件ID
        unsigned int blockId;       // 文件块ID
        unsigned long long size;    // 文件块大小
        unsigned long long begin;   // 文件块开始位置
        unsigned long long end;     // 文件块结束位置
        std::vector<uint8_t> data;  // 文件块数据
     ```
     */
    struct FileBlock
    {
        unsigned long long fileId;
        unsigned int blockId;
        unsigned long long size;
        unsigned long long begin;
        unsigned long long end;
        std::vector<uint8_t> data;
    };

    /**
     ### BlockFileObject 分块文件对象
     - 参数:
     ```c++
        unsigned long long id;      // 文件ID
        std::string name;           // 文件名
        std::string path;           // 文件路径
        std::string suffix;         // 文件后缀
        unsigned long long size;    // 文件大小
        std::string fileType;       // 文件类型
        std::vector<FileBlock> data;// 文件数据
     ```
     */
    struct BlockFileObject
    {
        unsigned long long id;
        std::string name;
        std::string path;
        std::string suffix;
        unsigned long long size;
        std::string fileType;
        std::vector<FileBlock> data;
    };


    /**
     ### 获取文件MIME类型
     - 使用示例:
     ```c++
     std::vector<uint8_t> data = FileRead("file.jpg");
     std::string mime = FileMimeType(data);
     return mime; // 返回 "image/jpeg"
     ```
     */
    std::string FileMimeType(const std::vector<uint8_t> &data)
    {
        for (const auto &sig : kSignatures)
            if (sig.mime && startsWith(data, sig))
                return sig.mime;
        if (data.size() >= 12 && startsWith(data, Signature{"\x52\x49\x46\x46", 4, nullptr}))
        {
            if (data[8] == 0x57 && data[9] == 0x41 && data[10] == 0x56 && data[11] == 0x45)
                return "audio/x-wav";
            if (data[8] == 0x41 && data[9] == 0x56 && data[10] == 0x49 && data[11] == 0x20)
                return "video/x-msvideo";
        }
        if (data.size() >= 12 && data[4] == 0x66 && data[5] == 0x74 && data[6] == 0x79 && data[7] == 0x70)
            return "video/mp4";
        return "application/octet-stream";
    }

    /**
     ### 读取文件并返回二进制数据
     - 使用示例:
     ```c++
     std::string path = "file.jpg";
     std::vector<uint8_t> data = HPEFileAPI::readFileToUint8Vector(path);
     return data; // 返回二进制数据
     ```
     */
    std::vector<std::uint8_t> readFileToUint8Vector(const std::string &path)
    {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file)
            throw std::runtime_error("无法打开文件: " + path);
        std::streamsize size = file.tellg();
        if (size == -1)
            throw std::runtime_error("获取文件大小失败: " + path);
        file.seekg(0, std::ios::beg);
        std::vector<std::uint8_t> buffer(static_cast<size_t>(size));
        if (!file.read(reinterpret_cast<char *>(buffer.data()), size))
            throw std::runtime_error("读取文件内容失败: " + path);
        return buffer;
    }

    /**
     ### 读取文件
     - 使用示例:
     ```c++
     std::string path = "file.jpg";
     HPEFileAPI::FileObject buffer = HPEFileAPI::readFile(path);
     return buffer; // 返回文件对象
     ```
     */
    static FileObject readFile(const std::string &path)
    {
        FileObject files;
        auto now = std::chrono::system_clock::now();
        auto time_t_now = std::chrono::system_clock::to_time_t(now);
        files.id = static_cast<long long>(time_t_now);
        files.name = path.substr(path.find_last_of("/\\") + 1);
        files.suffix = path.substr(path.find_last_of(".") + 1);
        files.path = path;
        files.data = readFileToUint8Vector(path);
        files.size = static_cast<unsigned int>(files.data.size());
        files.fileType = FileMimeType(files.data);
        return files;
    }

    /**
     ### 读取文件并分块
     - 使用示例:
     ```c++
     std::string path = "file.jpg";
     HPEFileAPI::BlockFileObject buffer = HPEFileAPI::readFileToBlocks(path);
     return buffer; // 返回分片文件对象
     */
    static BlockFileObject readFileToBlocks(const std::string &path, unsigned int blockSize = 1024 * 1024)
    {
        // 打开文件（二进制模式）
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file)
            throw std::runtime_error("无法打开文件: " + path);

        // 获取文件大小
        std::streamsize totalSize = file.tellg();
        if (totalSize == -1)
            throw std::runtime_error("获取文件大小失败: " + path);

        // 生成文件ID（与 readFile 保持一致，使用当前时间戳）
        auto now = std::chrono::system_clock::now();
        auto time_t_now = std::chrono::system_clock::to_time_t(now);
        long long fileId = static_cast<long long>(time_t_now);

        // 提取文件名和后缀
        std::string name = path.substr(path.find_last_of("/\\") + 1);
        std::string suffix = path.substr(path.find_last_of(".") + 1);

        // 读取文件头部（用于MIME识别）
        const size_t headerSize = 256; // 足够识别常见文件类型
        std::vector<uint8_t> header(headerSize);
        file.seekg(0, std::ios::beg);
        file.read(reinterpret_cast<char *>(header.data()), headerSize);
        size_t bytesRead = static_cast<size_t>(file.gcount());
        header.resize(bytesRead); // 调整到实际读取大小
        std::string mimeType = FileMimeType(header);

        // 准备分块
        std::vector<FileBlock> blocks;
        unsigned int blockId = 0;
        unsigned int offset = 0;

        // 重新定位到文件开头（准备顺序读取）
        file.clear(); // 清除 eofbit 和 failbit（如果之前读取头部后设置了 eof）
        file.seekg(0, std::ios::beg);

        while (offset < totalSize)
        {
            // 当前块实际大小
            unsigned int currentBlockSize = static_cast<unsigned int>(
                std::min(static_cast<std::streamsize>(blockSize), totalSize - offset));

            FileBlock block;
            block.fileId = static_cast<unsigned int>(fileId); // 注意类型转换，FileBlock::fileId 是 unsigned int
            block.blockId = blockId++;
            block.size = currentBlockSize;
            block.begin = offset;
            block.end = offset + currentBlockSize;

            // 读取块数据
            block.data.resize(currentBlockSize);
            if (!file.read(reinterpret_cast<char *>(block.data.data()), currentBlockSize))
            {
                throw std::runtime_error("读取文件块失败: " + path);
            }

            blocks.push_back(std::move(block));
            offset += currentBlockSize;
        }

        // 构造 BlockFileObject
        BlockFileObject result;
        result.id = fileId;
        result.name = std::move(name);
        result.suffix = std::move(suffix);
        result.path = path;
        result.size = static_cast<unsigned int>(totalSize);
        result.fileType = std::move(mimeType);
        result.data = std::move(blocks);

        return result;
    }
}
