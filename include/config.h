// 服务端IP
#define NET_SERVER_IP "127.0.0.1"
// 端口号
#define NET_PORT 6125
// 缓冲区大小
#define NET_BUFFER_SIZE (1 * 1024 * 1024)
// 最大连接数
#define NET_MAX_CONNECTIONS 10
// 最大客户端数
#define NET_MAX_CLIENTS 10
// 最大消息数
#define NET_MAX_MESSAGES (NET_MAX_CLIENTS * 100)
// 最大消息长度
#define NET_MAX_MESSAGE_LENGTH NET_BUFFER_SIZE
// 最大重试数
#define NET_MAX_RETRIES 5
// 最大重试间隔（毫秒）
#define NET_MAX_RETRY_INTERVAL 1000
// 最小重试间隔（毫秒）
#define NET_MIN_RETRY_INTERVAL 100
// 心跳间隔（秒）
#define NET_HEARTBEAT_INTERVAL_SEC 10
// 重连抖动因子
#define NET_JITTER_FACTOR 0.25