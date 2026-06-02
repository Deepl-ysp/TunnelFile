#include <string>
#include "netWork.h"
#include "HPEFileAPI.h"

// 基于TCP的Socket通信协议
#define HEADER = "hpe://$"
#define HEADER_MAX_SIZE = 1024

std::string readKey(const std::string& path = "key.key") {
    
}
const std::string PublicKey = readKey("./public.key");
const std::string PrivateKey = readKey("./private.key");
