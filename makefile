CXX = g++
CXXFLAGS = -std=c++17 -Wall -Iinclude -DASIO_STANDALONE -D_WIN32_WINNT=0x0A00
# 添加 -lmswsock 解决 AcceptEx 未定义引用
LDLIBS = -lws2_32 -lmswsock

BUILD_DIR = build
SRC_DIR = src

# 修改目标路径，包含子目录和 .exe 后缀
CLIENT_TARGET = $(BUILD_DIR)/client/client.exe
SERVER_TARGET = $(BUILD_DIR)/server/server.exe
TARGETS = $(CLIENT_TARGET) $(SERVER_TARGET)

all: $(TARGETS)

# 使用模式规则或单独规则创建目录
# 这里我们让每个目标依赖其所在的目录
$(CLIENT_TARGET): $(SRC_DIR)/client.cc | $(BUILD_DIR)/client
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDLIBS)

$(SERVER_TARGET): $(SRC_DIR)/server.cc | $(BUILD_DIR)/server
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDLIBS)

# 创建子目录的规则
$(BUILD_DIR)/client:
	mkdir -p $@

$(BUILD_DIR)/server:
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean