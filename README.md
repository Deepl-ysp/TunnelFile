# TunnelFile / 隧道文件 (TF)

## 项目简介

TunnelFile 是一款基于 TCP 的轻量级文件传输系统。它支持：

- **内网 → 公网**：将内网文件发送至公网服务器，并生成临时 HTTP 下载链接，方便其他公网服务获取。
- **公网 → 内网**：将公网文件传输回内网存储。

主要目的是降低云服务器的存储成本，解决数据盘容量小、价格高的问题，利用内网大容量存储作为扩展。

## 项目依赖

- [MSYS2](https://www.msys2.org/) —— Windows 下的软件构建与分发平台，提供 UCRT64 开发环境。
- [UCRT（通用 C 运行时）](https://github.com/microsoft/ucrt) —— 微软 C 运行时库，MSYS2 UCRT64 工具链的底层组件。
- [GNU Make](https://www.gnu.org/software/make/) —— 构建自动化工具。
- [GCC](https://gcc.gnu.org/) —— C++ 编译器。
- [ASIO](https://think-async.com/Asio/) —— 跨平台 C++ 网络库，支持异步 I/O。

## 快速开始

### 环境要求

- Windows / Linux / macOS
- GCC / Clang（支持 C++17 或更高版本）
- GNU Make
- MSYS2（Windows 用户）

### 构建项目

```bash
# 克隆仓库
git clone https://github.com/Deepl-ysp/TunnelFile.git
cd TunnelFile

# 使用 Make 构建
make
```

### 运行服务端

```bash
./build/server/server
```

服务端默认监听 `0.0.0.0:6125`，工作线程数为 4。具体配置请参考下文 **配置文件说明**。

## 配置文件说明

服务端使用 JSON 格式的配置文件，默认路径为 `build/server/config/config.json`。主要配置项如下：

```json
{
    "server": {
        "key": {
            "isKey": true,               // 是否启用密钥验证（默认 true）
            "PublicKey": "./keys/Ukey.key",   // 公钥路径
            "PrivateKey": "./keys/key.key"    // 私钥路径
        },
        "ip": "0.0.0.0",                // 监听 IP，默认 0.0.0.0
        "port": 6125,                   // 监听端口，默认 6125
        "WorkerNum": 4                  // 工作线程数，默认 4
    },
    "log": {
        "debug": {
            "logPath": "./log/debug_$.log",   // 日志路径，$ 为当前索引
            "logMaxSize": 50,                // 单文件最大记录数 MB
            "logIndex": 0                     // 日志文件索引
        },
        "info": {
            "logPath": "./log/info_$.log",
            "logMaxSize": 500,
            "logIndex": 0
        },
        "warn": {
            "logPath": "./log/warn_$.log",
            "logMaxSize": 500,
            "logIndex": 0
        },
        "error": {
            "logPath": "./log/error_$.log",
            "logMaxSize": 500,
            "logIndex": 0
        },
        "useLogs": ["debug"]            // 启用的日志级别，可配置多个
    },
    "HPE": {}                           // HPE 协议扩展配置（暂未使用）
}
```

## 项目结构

```
TunnelFile/
├── include/          # 头文件目录
│   ├── HPE.h         # HPE 协议核心定义
│   ├── HPEFileAPI.h  # HPE 文件 API
│   ├── config.h      # 配置解析相关
│   └── netWork.h     # 网络相关工具
├── src/              # 源文件目录
│   ├── server.cc     # 服务端主程序
│   └── client.cc     # 客户端主程序
├── test/             # 测试代码
│   ├── HPECrypt.h    # 加解密示例（仅供学习参考，不可直接用于生产环境）
│   └── ctest.cc      # 单元测试
├── build/            # 构建输出目录
│   └── server/config/
│       └── config.json  # 默认配置文件
└── Makefile          # 构建脚本
```

> **安全警告**：`test/HPECrypt.h` 中的加解密实现仅用于演示 HPE 协议的基本功能，**其密钥和算法均为公开示例**。若直接使用，攻击者可通过逆向工程轻易推导密钥，造成数据泄露。  
> **生产环境务必**：
> - 自行实现加解密规则（如使用非对称密钥动态协商会话密钥）；
> - 使用成熟的安全库（OpenSSL、libsodium 等）；
> - 将密钥存储在安全的密钥管理系统（KMS）或环境变量中，**禁止硬编码**。

## 贡献指南

欢迎提交 Issue 和 Pull Request。

1. Fork 本仓库
2. 创建你的特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交你的更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 打开一个 Pull Request

## 许可证

本项目采用 [MIT License](LICENSE) 进行许可。
```text
MIT License

Copyright (c) 2026 Deepl-ysp

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```


## 联系方式

项目作者：Deepl-ysp（老橙子ACK）

GitHub：[Deepl-ysp/TunnelFile](https://github.com/Deepl-ysp/TunnelFile)