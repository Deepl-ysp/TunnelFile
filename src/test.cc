// test.cc
#include "HPEFileAPI.h"
#include <iostream>
#include <cassert>
#include <fstream>
#include <cstdlib>
#include <stdexcept>
#include <vector>
#include <cstdint>
#include <windows.h>

// 辅助：创建临时测试文件（内容+后缀）
static std::string createTempFile(const std::string& content, const std::string& suffix = ".tmp") {
    std::string filename = "test_" + std::to_string(std::rand()) + suffix;
    std::ofstream out(filename, std::ios::binary);
    out.write(content.data(), content.size());
    out.close();
    return filename;
}

// 重载一个接受 vector<uint8_t> 的 createTempFile，方便测试二进制数据
static std::string createTempFile(const std::vector<uint8_t>& content, const std::string& suffix = ".tmp") {
    std::string filename = "test_" + std::to_string(std::rand()) + suffix;
    std::ofstream out(filename, std::ios::binary);
    out.write(reinterpret_cast<const char*>(content.data()), content.size());
    out.close();
    return filename;
}

int main() {
    using namespace HPEFileAPI;

    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);

    // 测试 PNG
    std::string pngContent = "\x89PNG\r\n\x1a\n";
    std::string pngFile = createTempFile(pngContent, ".png");
    FileObject obj = readFile(pngFile);
    assert(obj.fileType == "image/png");
    assert(obj.suffix == "png");
    assert(obj.size == pngContent.size());
    std::cout << "[PASS] PNG detection\n";

    // 测试 JPEG - 修复：使用 vector<uint8_t> 避免转义问题
    std::vector<uint8_t> jpegContent = {0xFF, 0xD8, 0xFF, 0xE0, 'a', 'b', 'c'};
    std::string jpgFile = createTempFile(jpegContent, ".jpg");
    obj = readFile(jpgFile);
    assert(obj.fileType == "image/jpeg");
    assert(obj.suffix == "jpg");
    std::cout << "[PASS] JPEG detection\n";

    // 测试文本文件（无特殊魔数）
    std::string txtContent = "Hello World";
    std::string txtFile = createTempFile(txtContent, ".txt");
    obj = readFile(txtFile);
    assert(obj.fileType == "application/octet-stream");
    assert(obj.suffix == "txt");
    assert(obj.size == txtContent.size());
    std::cout << "[PASS] Text file fallback\n";

    // 测试空文件
    std::string emptyFile = createTempFile("", ".empty");
    obj = readFile(emptyFile);
    assert(obj.size == 0);
    assert(obj.fileType == "application/octet-stream");
    std::cout << "[PASS] Empty file\n";

    // 测试不存在的文件（期望抛出异常）
    bool caught = false;
    try {
        obj = readFile("this_file_does_not_exist_xyz");
    } catch (const std::runtime_error& e) {
        caught = true;
        std::cout << "[PASS] Exception for missing file: " << e.what() << "\n";
    }
    assert(caught);

    // 清理临时文件
    std::remove(pngFile.c_str());
    std::remove(jpgFile.c_str());
    std::remove(txtFile.c_str());
    std::remove(emptyFile.c_str());

    std::cout << "All tests passed.\n";
    return 0;
}