// netWork.h
// ============================================================================
// 基于 ASIO 的轻量级 TCP 网络库（Header-Only）
//
// === 快速上手 ===
//
//   【服务端】
//     asio::io_context io;
//     auto server = std::make_shared<net::TcpServer>(io, "0.0.0.0", 6125);
//     server->set_on_message([](auto session, const std::string& data) {
//         std::cout << "收到: " << data << std::endl;
//         session->send("回声: " + data);          // 回复该客户端
//     });
//     server->start();
//     io.run();
//
//   【客户端】
//     asio::io_context io;
//     auto client = std::make_shared<net::TcpClient>(io, "127.0.0.1", 6125);
//     client->set_on_message([](const std::string& data) {
//         std::cout << "收到: " << data << std::endl;
//     });
//     client->set_on_connected([]() { std::cout << "已连接" << std::endl; });
//     client->connect();                           // 自动重连
//     io.run();
//
//   【直接使用 Session（高级）】
//     auto session = std::make_shared<net::TcpSession>(io, std::move(socket));
//     session->set_on_message([](auto self, const std::string& data) { ... });
//     session->start();
//
// === 线程模型 ===
//   所有回调在 io_context::run() 所在线程执行。
//   若使用多个线程运行 io_context::run()，回调可能在不同线程执行，
//   此时接收回调是串行的（ASIO 保证同一 socket 的 handler 不会并发），
//   但不同 Session 之间可能并发，用户需自行保护共享数据。
//
// === 协议格式 ===
//   [4 字节大端长度] [N 字节负载]
//   内部心跳消息 "__HB_PING__" / "__HB_PONG__" 对用户透明。
//
// === 配置方式 ===
//   在 #include "netWork.h" 之前 #include "config.h" 覆盖默认宏，
//   或直接 #define 所需宏。详见 config.h。
// ============================================================================
#pragma once

// ==================== 默认配置（用户可在包含本文件前覆盖） ====================
#ifndef NET_SERVER_IP
    #ifdef ServerIP
        #define NET_SERVER_IP ServerIP
    #else
        #define NET_SERVER_IP "127.0.0.1"
    #endif
#endif

#ifndef NET_PORT
    #ifdef Port
        #define NET_PORT Port
    #else
        #define NET_PORT 6125
    #endif
#endif

#ifndef NET_BUFFER_SIZE
    #ifdef BufferSize
        #define NET_BUFFER_SIZE BufferSize
    #else
        #define NET_BUFFER_SIZE (1 * 1024 * 1024)
    #endif
#endif

#ifndef NET_MAX_CONNECTIONS
    #ifdef MaxConnections
        #define NET_MAX_CONNECTIONS MaxConnections
    #else
        #define NET_MAX_CONNECTIONS 10
    #endif
#endif

#ifndef NET_MAX_CLIENTS
    #ifdef MaxClients
        #define NET_MAX_CLIENTS MaxClients
    #else
        #define NET_MAX_CLIENTS 10
    #endif
#endif

#ifndef NET_MAX_MESSAGES
    #ifdef MaxMessages
        #define NET_MAX_MESSAGES MaxMessages
    #else
        #define NET_MAX_MESSAGES (NET_MAX_CLIENTS * 100)
    #endif
#endif

#ifndef NET_MAX_MESSAGE_LENGTH
    #ifdef MaxMessageLength
        #define NET_MAX_MESSAGE_LENGTH MaxMessageLength
    #else
        #define NET_MAX_MESSAGE_LENGTH NET_BUFFER_SIZE
    #endif
#endif

#ifndef NET_MAX_RETRIES
    #ifdef MaxRetries
        #define NET_MAX_RETRIES MaxRetries
    #else
        #define NET_MAX_RETRIES 5
    #endif
#endif

#ifndef NET_MAX_RETRY_INTERVAL
    #ifdef MaxRetryInterval
        #define NET_MAX_RETRY_INTERVAL MaxRetryInterval
    #else
        #define NET_MAX_RETRY_INTERVAL 1000
    #endif
#endif

#ifndef NET_MIN_RETRY_INTERVAL
    #ifdef MinRetryInterval
        #define NET_MIN_RETRY_INTERVAL MinRetryInterval
    #else
        #define NET_MIN_RETRY_INTERVAL 100
    #endif
#endif

#ifndef NET_HEARTBEAT_INTERVAL_SEC
    #ifdef HeartbeatIntervalSec
        #define NET_HEARTBEAT_INTERVAL_SEC HeartbeatIntervalSec
    #else
        #define NET_HEARTBEAT_INTERVAL_SEC 10
    #endif
#endif

#ifndef NET_JITTER_FACTOR
    #ifdef JitterFactor
        #define NET_JITTER_FACTOR JitterFactor
    #else
        #define NET_JITTER_FACTOR 0.25
    #endif
#endif

#ifndef _WIN32_WINNT
    #define _WIN32_WINNT 0x0A00
#endif

#include <asio.hpp>
#include <functional>
#include <memory>
#include <queue>
#include <mutex>
#include <atomic>
#include <chrono>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <iomanip>
#include <random>
#include <cstdint>
#include <unordered_set>
#include <vector>

// ==================== 导出宏（DLL 可选） ====================
#ifdef _WIN32
    #ifdef GENERIC_SOCKET_EXPORTS
        #define GENERIC_SOCKET_API __declspec(dllexport)
    #else
        #define GENERIC_SOCKET_API __declspec(dllimport)
    #endif
#else
    #define GENERIC_SOCKET_API __attribute__((visibility("default")))
#endif

namespace net {

// ==================== 内部工具函数 ====================

inline void writeErrorLog(const std::string& msg) {
    try {
        std::filesystem::create_directories("./log");
        std::ofstream file("./log/error.log", std::ios::app);
        if (file.is_open()) {
            auto now = std::chrono::system_clock::now();
            std::time_t now_c = std::chrono::system_clock::to_time_t(now);
            file << std::put_time(std::localtime(&now_c), "%Y-%m-%d %H:%M:%S") << " - " << msg << std::endl;
        }
    } catch (...) {}
}

inline constexpr const char* HEARTBEAT_PING = "__HB_PING__";
inline constexpr const char* HEARTBEAT_PONG = "__HB_PONG__";

// ==================== 前向声明 ====================
class TcpSession;

// ========================================================================
// TcpSession —— 单条 TCP 连接（长度前缀协议 + 心跳）
// ========================================================================
// 由 TcpServer::do_accept() 或 TcpClient::do_connect() 内部创建，
// 也可由用户直接构造（传入已连接的 socket）实现自定义 accept 逻辑。
// ========================================================================
class GENERIC_SOCKET_API TcpSession : public std::enable_shared_from_this<TcpSession> {
public:
    using Ptr       = std::shared_ptr<TcpSession>;
    using WeakPtr   = std::weak_ptr<TcpSession>;
    using OnMessage = std::function<void(Ptr /*session*/, const std::string& /*data*/)>;
    using OnDisconnect = std::function<void(Ptr /*session*/)>;

    TcpSession(asio::io_context& io, asio::ip::tcp::socket socket)
        : io_(io)
        , socket_(std::move(socket))
        , heartbeat_timer_(io)
        , strand_(io)
    {}

    ~TcpSession() { close(); }

    // ---- 禁用拷贝 ----
    TcpSession(const TcpSession&) = delete;
    TcpSession& operator=(const TcpSession&) = delete;

    // ========== 公开 API ==========

    void start() {
        connected_ = true;
        doReadHeader();
        startHeartbeat();
    }

    void send(const std::string& data) {
        sendBinary(data.data(), data.size());
    }

    void send(const std::vector<uint8_t>& data) {
        sendBinary(data.data(), data.size());
    }

    void send(const void* data, size_t len) {
        sendBinary(data, len);
    }

    void close() {
        if (stopped_.exchange(true)) return;
        connected_ = false;
        asio::error_code ec;
        heartbeat_timer_.cancel();
        socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        socket_.close(ec);
    }

    bool is_connected() const { return connected_; }

    void set_on_message(OnMessage cb)   { on_message_   = std::move(cb); }
    void set_on_disconnect(OnDisconnect cb) { on_disconnect_ = std::move(cb); }

    asio::ip::tcp::socket& socket() { return socket_; }

private:
    // ========== 读（长度前缀协议） ==========

    void doReadHeader() {
        if (stopped_ || !connected_) return;
        auto self = shared_from_this();
        asio::async_read(socket_, asio::buffer(&header_buf_, sizeof(header_buf_)),
            asio::bind_executor(strand_,
                [this, self](asio::error_code ec, std::size_t) {
                    if (stopped_) return;
                    if (ec) {
                        writeErrorLog("TcpSession read header: " + ec.message());
                        handleDisconnect();
                        return;
                    }
                    uint32_t len = ntohl(header_buf_);
                    if (len > NET_MAX_MESSAGE_LENGTH) {
                        writeErrorLog("TcpSession invalid packet length: " + std::to_string(len));
                        handleDisconnect();
                        return;
                    }
                    doReadBody(len);
                }));
    }

    void doReadBody(uint32_t len) {
        if (stopped_ || !connected_) return;
        body_buf_.resize(len);
        auto self = shared_from_this();
        asio::async_read(socket_, asio::buffer(body_buf_),
            asio::bind_executor(strand_,
                [this, self, len](asio::error_code ec, std::size_t) {
                    if (stopped_) return;
                    if (ec) {
                        writeErrorLog("TcpSession read body: " + ec.message());
                        handleDisconnect();
                        return;
                    }
                    std::string data(body_buf_.begin(), body_buf_.end());
                    handleData(std::move(data));
                }));
    }

    void handleData(const std::string& data) {
        if (data == HEARTBEAT_PING) {
            send(HEARTBEAT_PONG);
            doReadHeader();
            return;
        }
        if (data == HEARTBEAT_PONG) {
            heartbeat_missed_ = 0;
            doReadHeader();
            return;
        }

        if (on_message_) {
            on_message_(shared_from_this(), data);
        }

        doReadHeader();
    }

    // ========== 写（串行发送队列） ==========

    void sendBinary(const void* data, size_t len) {
        if (!connected_) {
            writeErrorLog("TcpSession::send failed: not connected");
            return;
        }
        if (data == nullptr || len == 0) {
            writeErrorLog("TcpSession::send failed: invalid data");
            return;
        }
        bool need_write = false;
        {
            std::lock_guard<std::mutex> lock(send_mutex_);
            send_queue_.emplace(static_cast<const char*>(data), len);
            if (!writing_) {
                writing_ = true;
                need_write = true;
            }
        }
        if (need_write) {
            doWrite();
        }
    }

    void doWrite() {
        if (stopped_ || !connected_) return;
        std::string data;
        {
            std::lock_guard<std::mutex> lock(send_mutex_);
            if (send_queue_.empty()) {
                writing_ = false;
                return;
            }
            data = std::move(send_queue_.front());
            send_queue_.pop();
        }

        uint32_t net_len = htonl(static_cast<uint32_t>(data.size()));
        std::array<asio::const_buffer, 2> buffers = {
            asio::buffer(&net_len, sizeof(net_len)),
            asio::buffer(data)
        };

        auto self = shared_from_this();
        asio::async_write(socket_, buffers,
            asio::bind_executor(strand_,
                [this, self](asio::error_code ec, std::size_t) {
                    if (stopped_) return;
                    if (ec) {
                        writeErrorLog("TcpSession write: " + ec.message());
                        handleDisconnect();
                        return;
                    }
                    doWrite();
                }));
    }

    // ========== 心跳 ==========

    void startHeartbeat() {
        if (stopped_ || !connected_) return;
        heartbeat_timer_.expires_after(std::chrono::seconds(NET_HEARTBEAT_INTERVAL_SEC));
        auto self = shared_from_this();
        heartbeat_timer_.async_wait(
            asio::bind_executor(strand_,
                [this, self](asio::error_code ec) {
                    if (stopped_) return;
                    if (ec == asio::error::operation_aborted) return;
                    if (ec) {
                        writeErrorLog("TcpSession heartbeat timer: " + ec.message());
                        handleDisconnect();
                        return;
                    }
                    if (!connected_) return;

                    send(HEARTBEAT_PING);
                    ++heartbeat_missed_;
                    if (heartbeat_missed_ >= NET_MAX_RETRIES) {
                        writeErrorLog("TcpSession heartbeat timeout, closing");
                        handleDisconnect();
                        return;
                    }
                    startHeartbeat();
                }));
    }

    // ========== 断开处理 ==========

    void handleDisconnect() {
        if (!connected_) return;
        connected_ = false;
        asio::error_code ec;
        heartbeat_timer_.cancel();
        socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        socket_.close(ec);

        if (on_disconnect_) {
            on_disconnect_(shared_from_this());
        }
    }

private:
    asio::io_context& io_;
    asio::ip::tcp::socket socket_;
    asio::steady_timer heartbeat_timer_;
    asio::io_context::strand strand_;

    std::atomic<bool> connected_{false};
    std::atomic<bool> stopped_{false};

    uint32_t header_buf_{0};
    std::vector<char> body_buf_;

    std::mutex send_mutex_;
    std::queue<std::string> send_queue_;
    bool writing_{false};

    int heartbeat_missed_{0};

    OnMessage on_message_;
    OnDisconnect on_disconnect_;
};

/**
 * @brief TcpServer —— TCP 服务端（监听 + accept + 管理 Session）
 * @note 支持绑定到指定 IP 地址（如 "192.168.1.100"）或所有接口（"0.0.0.0"）
 * 通过 on_message 回调接收消息，可获取来源 Session 并回复
 * 自动清理已断开的 Session
 */
class GENERIC_SOCKET_API TcpServer : public std::enable_shared_from_this<TcpServer> {
public:
    using Ptr        = std::shared_ptr<TcpServer>;
    using SessionPtr = TcpSession::Ptr;

    /**
     * @brief 绑定IP构造函数
     * @param io      asio::io_context 对象
     * @param bind_ip 绑定的 IP 地址
     * @param port    绑定的端口
     */
    TcpServer(asio::io_context& io, const std::string& bind_ip, uint16_t port)
        : io_(io)
        , acceptor_(io)
    {
        auto addr = asio::ip::make_address(bind_ip);
        asio::ip::tcp::endpoint endpoint(addr, port);
        acceptor_.open(endpoint.protocol());
        acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true));
        acceptor_.bind(endpoint);
        acceptor_.listen(NET_MAX_CONNECTIONS);
    }

    /**
     * @brief 非绑定IP构造函数
     * @param io   asio::io_context 对象
     * @param port 端口号
     */
    TcpServer(asio::io_context& io, uint16_t port)
        : TcpServer(io, "0.0.0.0", port)
    {}

    /**
     * @brief 析构函数
     */
    ~TcpServer() { stop(); }

    /**
     * @brief 启动服务
     */
    TcpServer(const TcpServer&) = delete;
    TcpServer& operator=(const TcpServer&) = delete;

    /**
     * @brief 启动服务
     */
    void start() { doAccept(); }

    /**
     * @brief 停止服务
     */
    void stop() {
        if (stopped_.exchange(true)) return;
        asio::error_code ec;
        acceptor_.close(ec);

        std::unique_lock<std::mutex> lock(sessions_mutex_);
        auto sessions = std::move(sessions_);
        lock.unlock();

        for (auto& s : sessions) {
            s->close();
        }
    }

    /**
     * @brief 设置新连接回调
     * @param cb 回调函数
     * @note 回调函数参数为SessionPtr session指针
     */
    void set_on_new_session(std::function<void(SessionPtr)> cb) {
        on_new_session_ = std::move(cb);
    }

    /**
     * @brief 设置消息回调
     * @param cb 回调函数
     * @note 回调函数参数为SessionPtr session指针和std::string message
     */
    void set_on_message(std::function<void(SessionPtr, const std::string&)> cb) {
        on_message_ = std::move(cb);
    }

    /**
     * @brief 启动服务
     */
    void broadcast(const std::string& data) {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        for (auto& s : sessions_) {
            if (s->is_connected()) {
                s->send(data);
            }
        }
    }

    size_t session_count() const {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        return sessions_.size();
    }

private:
    void doAccept() {
        if (stopped_) return;

        auto self = shared_from_this();
        auto sock = std::make_shared<asio::ip::tcp::socket>(io_);
        acceptor_.async_accept(*sock,
            [this, self, sock](asio::error_code ec) {
                if (stopped_) return;

                if (!ec) {
                    if (sessions_.size() >= static_cast<size_t>(NET_MAX_CLIENTS)) {
                        writeErrorLog("TcpServer max clients reached, rejecting");
                        asio::error_code ign;
                        sock->close(ign);
                    } else {
                        auto session = std::make_shared<TcpSession>(io_, std::move(*sock));

                        session->set_on_message(
                            [this, weak_s = TcpSession::WeakPtr(session)]
                            (TcpSession::Ptr, const std::string& data) {
                                if (on_message_) {
                                    if (auto s = weak_s.lock()) {
                                        on_message_(s, data);
                                    }
                                }
                            });

                        session->set_on_disconnect(
                            [this, weak_s = TcpSession::WeakPtr(session)]
                            (TcpSession::Ptr) {
                                std::lock_guard<std::mutex> lock(sessions_mutex_);
                                if (auto s = weak_s.lock()) {
                                    sessions_.erase(s);
                                }
                            });

                        {
                            std::lock_guard<std::mutex> lock(sessions_mutex_);
                            sessions_.insert(session);
                        }

                        session->start();

                        if (on_new_session_) {
                            on_new_session_(session);
                        }
                    }
                } else {
                    writeErrorLog("TcpServer accept: " + ec.message());
                }

                doAccept();
            });
    }

private:
    asio::io_context& io_;
    asio::ip::tcp::acceptor acceptor_;
    std::atomic<bool> stopped_{false};

    mutable std::mutex sessions_mutex_;
    std::unordered_set<SessionPtr> sessions_;

    std::function<void(SessionPtr)> on_new_session_;
    std::function<void(SessionPtr, const std::string&)> on_message_;
};

/**
 * @brief TcpClient —— TCP 客户端（连接 + 自动重连 + 心跳）
 * @note connect() 后自动维护连接（指数退避重连 + 随机抖动）
 * 通过回调接收消息和连接/断开事件
 */
class GENERIC_SOCKET_API TcpClient : public std::enable_shared_from_this<TcpClient> {
public:
    using Ptr = std::shared_ptr<TcpClient>;

    /**
     * @brief TcpClient —— TCP 构造函数
     * @param io asio::io_context
     * @param host 服务器地址
     * @param port 服务器端口
     */
    TcpClient(asio::io_context& io, const std::string& host, uint16_t port)
        : io_(io)
        , host_(host)
        , port_(port)
        , reconnect_timer_(io)
    {}

    /**
     * @brief TcpClient —— TCP 析构函数
     */
    ~TcpClient() { disconnect(); }

    TcpClient(const TcpClient&) = delete;
    TcpClient& operator=(const TcpClient&) = delete;

    // ========== 公开 API ==========

    /**
     * @brief TcpClient —— TCP 连接
     */
    void connect() {
        if (stopped_) return;
        should_reconnect_ = true;
        doConnect();
    }

    /**
     * @brief TcpClient —— TCP 断开
     */
    void disconnect() {
        should_reconnect_ = false;
        stopped_ = true;
        asio::error_code ec;
        reconnect_timer_.cancel();
        if (session_) {
            session_->close();
            session_.reset();
        }
    }

    /**
     * @brief TcpClient —— TCP 发送数据
     * @param data
     */
    void send(const std::string& data) {
        if (session_ && session_->is_connected()) {
            session_->send(data);
        } else {
            writeErrorLog("TcpClient::send failed: not connected");
        }
    }

    void send(const std::vector<uint8_t>& data) {
        if (session_ && session_->is_connected()) {
            session_->send(data);
        } else {
            writeErrorLog("TcpClient::send failed: not connected");
        }
    }

    void send(const void* data, size_t len) {
        if (session_ && session_->is_connected()) {
            session_->send(data, len);
        } else {
            writeErrorLog("TcpClient::send failed: not connected");
        }
    }

    /**
     * @brief TcpClient —— TCP 是否已连接
     * @return boolean
     */
    bool is_connected() const {
        return session_ && session_->is_connected();
    }

    /**
     * @brief TcpClient —— TCP 设置消息回调
     * @param cb 消息回调
     */
    void set_on_message(std::function<void(const std::string&)> cb) {
        on_message_ = std::move(cb);
    }

    /**
     * @brief TcpClient —— TCP 断开连接
     * @param cb 断开连接回调
     */
    void set_on_disconnect(std::function<void()> cb) {
        on_disconnect_ = std::move(cb);
    }

    /**
     * @brief TcpClient —— TCP 连接成功
     * @param cb 连接成功回调
     */
    void set_on_connected(std::function<void()> cb) {
        on_connected_ = std::move(cb);
    }

private:
    void doConnect() {
        if (stopped_) return;

        asio::error_code ec;
        auto addr = asio::ip::make_address(host_, ec);
        if (ec) {
            writeErrorLog("TcpClient resolve: " + ec.message());
            scheduleReconnect();
            return;
        }

        auto sock = std::make_shared<asio::ip::tcp::socket>(io_);
        asio::ip::tcp::endpoint endpoint(addr, port_);

        auto self = shared_from_this();
        sock->async_connect(endpoint,
            [this, self, sock](asio::error_code ec) {
                if (stopped_) return;

                if (!ec) {
                    session_ = std::make_shared<TcpSession>(io_, std::move(*sock));

                    session_->set_on_message(
                        [this](TcpSession::Ptr, const std::string& data) {
                            if (on_message_) {
                                on_message_(data);
                            }
                        });

                    session_->set_on_disconnect(
                        [this](TcpSession::Ptr) {
                            if (on_disconnect_) {
                                on_disconnect_();
                            }
                            if (should_reconnect_ && !stopped_) {
                                scheduleReconnect();
                            }
                        });

                    session_->start();
                    reconnect_interval_ms_ = NET_MIN_RETRY_INTERVAL;

                    if (on_connected_) {
                        on_connected_();
                    }
                } else {
                    writeErrorLog("TcpClient connect: " + ec.message());
                    scheduleReconnect();
                }
            });
    }

    void scheduleReconnect() {
        if (stopped_ || !should_reconnect_) return;
        auto self = shared_from_this();

        int interval = reconnect_interval_ms_;
        int jitter = 0;
        if (interval > 0) {
            static thread_local std::mt19937 rng(std::random_device{}());
            int max_jitter = static_cast<int>(interval * NET_JITTER_FACTOR);
            if (max_jitter > 0) {
                std::uniform_int_distribution<int> dist(-max_jitter, max_jitter);
                jitter = dist(rng);
            }
        }
        int wait_ms = interval + jitter;
        if (wait_ms < 1) wait_ms = 1;

        reconnect_timer_.expires_after(std::chrono::milliseconds(wait_ms));
        reconnect_timer_.async_wait(
            [this, self](asio::error_code ec) {
                if (stopped_) return;
                if (ec == asio::error::operation_aborted) return;
                if (ec) {
                    writeErrorLog("TcpClient reconnect timer: " + ec.message());
                    return;
                }
                doConnect();

                int next = reconnect_interval_ms_ * 2;
                if (next > NET_MAX_RETRY_INTERVAL) next = NET_MAX_RETRY_INTERVAL;
                reconnect_interval_ms_ = next;
            });
    }

private:
    asio::io_context& io_;
    std::string host_;
    uint16_t port_;
    asio::steady_timer reconnect_timer_;

    std::shared_ptr<TcpSession> session_;

    std::atomic<bool> stopped_{false};
    std::atomic<bool> should_reconnect_{false};
    int reconnect_interval_ms_{NET_MIN_RETRY_INTERVAL};

    std::function<void(const std::string&)> on_message_;
    std::function<void()> on_disconnect_;
    std::function<void()> on_connected_;
};

} // namespace net