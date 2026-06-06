#include <iostream>
#include <thread>
#include "config.h"
#include "HPENetWork.h"

int main() {
    #ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    std::cout << "正在启动客户端..." << std::endl;
    #endif
    asio::io_context io;
    auto client = std::make_shared<HPENetWork::TcpClient>(io, NET_SERVER_IP, static_cast<uint16_t>(NET_PORT));
    client->set_on_connected([]() {
        std::cout << "已连接到服务器" << std::endl;
    });
    client->set_on_message([client](const std::string& data) {
        std::cout << "收到: " << data << std::endl;
        client->send("我已收到你的消息");
    });
    client->set_on_disconnect([]() {
        std::cout << "连接断开，正在重连..." << std::endl;
        exit(1);
    });
    client->connect();
    std::thread io_thread([&io] { io.run(); });
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line == "quit" || line == "exit") break;
        if (client->is_connected()) 
            client->send(line);
        else 
            std::cout << "未连接" << std::endl;
    }
    client->disconnect();
    io.stop();
    io_thread.join();
}