#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <fstream>

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

namespace HPEFileAPI
{
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
     * @brief FileObject 通用建议文件对象
     * @param name 文件名
     * @param suffix 文件后缀
     * @param path 文件路径
     * @param fileType 文件类型
     * @param size 文件大小 (字节)
     * @param data 文件数据 (二进制)
     */
    struct FileObject
    {
        std::string name;
        std::string suffix;
        std::string path;
        unsigned int size;
        std::string fileType;
        std::vector<uint8_t> data;
    };

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

    FileObject readFile(const std::string &path)
    {
        FileObject files;
        files.name = path.substr(path.find_last_of("/\\") + 1);
        files.suffix = path.substr(path.find_last_of(".") + 1);
        files.path = path;
        files.data = readFileToUint8Vector(path);
        files.size = static_cast<unsigned int>(files.data.size());
        files.fileType = FileMimeType(files.data);
        return files;
    }
}
