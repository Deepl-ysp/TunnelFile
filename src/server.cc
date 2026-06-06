#include <iostream>
#include "config.h"
#include "HPENetWork.h"
#include "HPEFileAPI.h"

int main() {
    #ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    std::cout << "正在启动服务端..." << std::endl;
    #endif
    asio::io_context io;

    auto server = std::make_shared<HPENetWork::TcpServer>(io, NET_SERVER_IP, static_cast<uint16_t>(NET_PORT));

    server->set_on_message([](HPENetWork::TcpSession::Ptr session, const std::string& data) {
        std::cout << "收到[" << session.get() << "]: " << data << std::endl;
    });

    server->set_on_new_session([](HPENetWork::TcpSession::Ptr session) {
        std::cout << "新客户端连接: " << session.get() << std::endl;
        session->send("欢迎登陆服务器");
    });

    server->start();
    std::cout << "服务端已启动: " << NET_SERVER_IP << ":" << NET_PORT << std::endl;

    io.run();
}