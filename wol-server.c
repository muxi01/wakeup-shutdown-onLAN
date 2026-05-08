#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/udp.h>
#include <sys/types.h>
#include <semaphore.h>
#include <pthread.h>
#include <time.h>

#define BUFFER_SIZE 4096
#define DEFAULT_PORT 8080
#define MAX_CLIENTS 5

// CRC32 实现
#include <stdint.h>

static uint32_t crc32_table[256];
static int crc32_initialized = 0;

static void init_crc32() {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            crc = (crc & 1) ? ((crc >> 1) ^ 0xEDB88320) : (crc >> 1);
        }
        crc32_table[i] = crc;
    }
    crc32_initialized = 1;
}

static uint32_t crc32(const char *input, size_t len) {
    if (!crc32_initialized) init_crc32();
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc = (crc >> 8) ^ crc32_table[(crc ^ (uint8_t)input[i]) & 0xFF];
    }
    return crc ^ 0xFFFFFFFF;
}

static void crc32_hex(const char *input, char *output) {
    uint32_t val = crc32(input, strlen(input));
    snprintf(output, 9, "%08X", val);
}

// 生成8位随机字符串
static void generate_random_string(char *output, int len) {
    static const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    srand(time(NULL) ^ (unsigned long)output);
    for (int i = 0; i < len; i++)
        output[i] = chars[rand() % (sizeof(chars) - 1)];
    output[len] = '\0';
}

typedef struct {
    int port;
    int sleep_port;
    char sleep_msg[256];
    char password_seed[64];
} Config;

Config config = {DEFAULT_PORT, 9999, "shutdown", ""};

// 当前会话密钥
typedef struct {
    char random_str[9];
    char access_code[9];
    int valid;
} SessionKey;

SessionKey session = {{0}, {0}, 0};
sem_t client_sem;

// 发送 WOL 魔术包
int send_wol(const char *mac_str, const char *broadcast_ip) {
    unsigned char mac[6];
    unsigned char packet[102];
    int sock;
    struct sockaddr_in addr;

    // 解析 MAC 地址
    if (sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
        fprintf(stderr, "无效的 MAC 地址格式: %s\n", mac_str);
        return -1;
    }

    // 构建魔术包 (6字节 FF + 16 * MAC)
    memset(packet, 0xFF, 6);
    for (int i = 0; i < 16; i++) {
        memcpy(packet + 6 + i * 6, mac, 6);
    }

    // 创建 UDP socket
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("创建 socket 失败");
        return -1;
    }

    // 设置广播选项
    int broadcast = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));

    // 设置目标地址
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9);
    addr.sin_addr.s_addr = inet_addr(broadcast_ip);

    // 发送数据包
    ssize_t sent = sendto(sock, packet, sizeof(packet), 0,
                          (struct sockaddr *)&addr, sizeof(addr));
    close(sock);

    if (sent < 0) {
        perror("发送数据包失败");
        return -1;
    }

    return 0;
}

// 发送 UDP 关机广播
int send_shutdown_broadcast(const char *broadcast_ip, int port, const char *message) {
    int sock;
    struct sockaddr_in addr;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket failed");
        return -1;
    }

    int broadcast = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(broadcast_ip);

    ssize_t sent = sendto(sock, message, strlen(message), 0,
                          (struct sockaddr *)&addr, sizeof(addr));
    close(sock);

    if (sent < 0) {
        perror("send failed");
        return -1;
    }
    return 0;
}

// 发送 HTTP 响应
void send_response(int client_fd, int status_code, const char *status, const char *content_type, const char *body, int body_len) {
    char header[1024];
    int content_len = body_len > 0 ? body_len : strlen(body);

    snprintf(header, sizeof(header),
             "HTTP/1.1 %d %s\r\n"
             "Content-Type: %s\r\n"
             "Content-Length: %d\r\n"
             "Connection: close\r\n"
             "\r\n",
             status_code, status, content_type, content_len);

    write(client_fd, header, strlen(header));
    write(client_fd, body, content_len);
}

// URL 解码
void url_decode(char *dst, const char *src) {
    char a, b;
    while (*src) {
        if (*src == '%' && (a = src[1]) && (b = src[2])) {
            *dst++ = (a >= 'A' ? (a & 0xDF) - 'A' : a - '0') * 16 +
                     (b >= 'A' ? (b & 0xDF) - 'A' : b - '0');
            src += 3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

// 解析查询参数
void parse_params(char *params, char *mac, char *ip, char *code) {
    char *saveptr;
    char *pair = strtok_r(params, "&", &saveptr);

    while (pair) {
        char key[128], value[256];
        sscanf(pair, "%[^=]=%[^&]", key, value);
        url_decode(value, value);

        if (strcmp(key, "mac") == 0) {
            strncpy(mac, value, 17);
        } else if (strcmp(key, "ip") == 0) {
            strncpy(ip, value, 15);
        } else if (strcmp(key, "code") == 0) {
            strncpy(code, value, 63);
        }
        pair = strtok_r(NULL, "&", &saveptr);
    }
}

// 处理 HTTP 请求
void handle_request(int client_fd) {
    char buffer[BUFFER_SIZE];
    char method[16], url[256], version[16];
    char path_only[256], query[256] = {0};

    // 读取请求行
    if (read(client_fd, buffer, BUFFER_SIZE - 1) <= 0) return;
    buffer[BUFFER_SIZE - 1] = '\0';

    // 解析请求行
    sscanf(buffer, "%s %s %s", method, url, version);

    // 分离路径和查询参数
    char *query_ptr = strchr(url, '?');
    if (query_ptr) {
        strncpy(path_only, url, query_ptr - url);
        path_only[query_ptr - url] = '\0';
        strcpy(query, query_ptr + 1);
    } else {
        strcpy(path_only, url);
    }

    // 检查方法
    if (strcmp(method, "POST") != 0 && strcmp(method, "GET") != 0) {
        send_response(client_fd, 405, "Method Not Allowed",
                     "text/plain", "Only GET/POST methods are supported", 0);
        return;
    }

    // 首页
    if (strcmp(path_only, "/") == 0) {
        char response[1024] = {0};
        int resp_len;

        // 如果设置了密码种子，生成新的会话密钥
        if (config.password_seed[0] != '\0') {
            generate_random_string(session.random_str, 8);
            char crc_input[128];
            snprintf(crc_input, sizeof(crc_input), "%s%s", session.random_str, config.password_seed);
            char crc_output[9];
            crc32_hex(crc_input, crc_output);
            strncpy(session.access_code, crc_output, 8);
            session.access_code[8] = '\0';
            session.valid = 1;

            resp_len = snprintf(response, sizeof(response),
                "Wake-on-LAN Tool Usage\n\n"
                "Random Token: %s\n"
                "Access Code: 8 Byte code, please calculate it\n"
                "(Use this code once, then it expires)\n\n"
                "=== Wake-on-LAN ===\n"
                "  curl -X POST \"http://localhost:8080/wake?mac=AA:BB:CC:DD:EE:FF&code=XXXXXXXX\"\n"
                "  curl -X POST \"http://localhost:8080/wake?mac=AA:BB:CC:DD:EE:FF&ip=192.168.1.255&code=XXXXXXXX\"\n\n"
                "=== Shutdown Broadcast ===\n"
                "  curl -X POST \"http://localhost:8080/sleep?code=XXXXXXXX\"\n"
                "  curl -X POST \"http://localhost:8080/sleep?ip=192.168.1.255&code=XXXXXXXX\"\n",
                session.random_str);
        } else {
            resp_len = snprintf(response, sizeof(response),
                "Wake-on-LAN Tool Usage\n\n"
                "=== Wake-on-LAN ===\n"
                "  curl -X POST \"http://localhost:8080/wake?mac=AA:BB:CC:DD:EE:FF\"\n"
                "  curl -X POST \"http://localhost:8080/wake?mac=AA:BB:CC:DD:EE:FF&ip=192.168.1.255\"\n\n"
                "=== Shutdown Broadcast ===\n"
                "  curl -X POST \"http://localhost:8080/sleep\"\n"
                "  curl -X POST \"http://localhost:8080/sleep?ip=192.168.1.255\"\n");
        }

        send_response(client_fd, 200, "OK", "text/plain; charset=utf-8", response, resp_len);
        return;
    }

    // WOL 接口
    if (strcmp(path_only, "/wake") == 0) {
        char mac[18] = {0}, ip[16] = "255.255.255.255", code[64] = {0};

        // 优先从查询参数获取
        if (strlen(query) > 0) {
            parse_params(query, mac, ip, code);
        }

        // POST 请求时也解析请求体
        if (strcmp(method, "POST") == 0) {
            char *body = strstr(buffer, "\r\n\r\n");
            if (body) {
                body += 4;
                parse_params(body, mac, ip, code);
            }
        }

        // 验证访问码
        if (config.password_seed[0] != '\0') {
            if (!session.valid) {
                send_response(client_fd, 401, "Unauthorized",
                             "text/plain", "Please visit / to get a new access code", 0);
                return;
            }
            if (strcmp(code, session.access_code) != 0) {
                send_response(client_fd, 401, "Unauthorized",
                             "text/plain", "Invalid access code", 0);
                return;
            }
            session.valid = 0;  // 使密钥失效
        }

        if (mac[0] == '\0') {
            send_response(client_fd, 400, "Bad Request",
                         "text/plain", "Missing required parameter: mac", 0);
            return;
        }

        // 发送 WOL
        char response[256] = {0};
        int resp_len;
        if (send_wol(mac, ip) == 0) {
            resp_len = snprintf(response, sizeof(response),
                    "WOL packet sent!\nMAC: %s\nBroadcast IP: %s\n", mac, ip);
            send_response(client_fd, 200, "OK", "text/plain", response, resp_len);
        } else {
            send_response(client_fd, 500, "Internal Server Error",
                         "text/plain", "Failed to send WOL packet", 0);
        }
        return;
    }

    // Sleep 接口 - 发送 UDP 关机广播
    if (strcmp(path_only, "/sleep") == 0) {
        char ip[16] = "255.255.255.255", code[64] = {0};

        // 只从查询参数获取 ip 和 code
        if (strlen(query) > 0) {
            char *saveptr;
            char *pair = strtok_r(query, "&", &saveptr);
            while (pair) {
                char key[64] = {0}, value[256] = {0};
                sscanf(pair, "%[^=]=%[^\0]", key, value);
                url_decode(value, value);

                if (strcmp(key, "ip") == 0) {
                    strncpy(ip, value, sizeof(ip) - 1);
                } else if (strcmp(key, "code") == 0) {
                    strncpy(code, value, sizeof(code) - 1);
                }
                pair = strtok_r(NULL, "&", &saveptr);
            }
        }

        // POST 请求时也解析请求体
        if (strcmp(method, "POST") == 0) {
            char *body = strstr(buffer, "\r\n\r\n");
            if (body) {
                body += 4;
                char tmp_ip[16], tmp_code[64];
                parse_params(body, tmp_ip, tmp_ip, tmp_code);
                if (ip[0] == '\0' && tmp_ip[0] != '\0') {
                    strncpy(ip, tmp_ip, sizeof(ip) - 1);
                }
                if (code[0] == '\0' && tmp_code[0] != '\0') {
                    strncpy(code, tmp_code, sizeof(code) - 1);
                }
            }
        }

        // 验证访问码
        if (config.password_seed[0] != '\0') {
            if (!session.valid) {
                send_response(client_fd, 401, "Unauthorized",
                             "text/plain", "Please visit / to get a new access code", 0);
                return;
            }
            if (strcmp(code, session.access_code) != 0) {
                send_response(client_fd, 401, "Unauthorized",
                             "text/plain", "Invalid access code", 0);
                return;
            }
            session.valid = 0;  // 使密钥失效
        }

        char response[256] = {0};
        int resp_len;
        if (send_shutdown_broadcast(ip, config.sleep_port, config.sleep_msg) == 0) {
            resp_len = snprintf(response, sizeof(response),
                    "Shutdown broadcast sent!\nBroadcast IP: %s\nPort: %d\nMessage: %s\n",
                    ip, config.sleep_port, config.sleep_msg);
            send_response(client_fd, 200, "OK", "text/plain", response, resp_len);
        } else {
            send_response(client_fd, 500, "Internal Server Error",
                         "text/plain", "Failed to send shutdown broadcast", 0);
        }
        return;
    }

    // 其他路径
    send_response(client_fd, 403, "Forbidden", "text/plain", "Access denied", 0);
}

// HTTP 服务器
void start_server() {
    int server_fd, client_fd;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    // 初始化信号量
    sem_init(&client_sem, 0, MAX_CLIENTS);

    // 创建 socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("创建 socket 失败");
        exit(EXIT_FAILURE);
    }

    // 设置 socket 选项
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // 绑定地址
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(config.port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("绑定端口失败");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // 监听
    if (listen(server_fd, 10) < 0) {
        perror("监听失败");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Wake-on-LAN 服务已启动\n");
    printf("监听端口: %d\n", config.port);
    printf("WOL 接口: /wake\n");
    printf("Sleep 接口: /sleep\n");
    printf("最大连接数: %d\n", MAX_CLIENTS);
    printf("启动命令示例:\n");
    printf("  curl -X POST \"http://localhost:%d/wake?mac=AA:BB:CC:DD:EE:FF\"\n",config.port);
    printf("  curl -X POST \"http://localhost:%d/sleep\"\n", config.port);

    // 忽略子进程信号
    signal(SIGCHLD, SIG_IGN);

    // 接受连接
    while (1) {
        // 等待信号量（限制连接数）
        sem_wait(&client_sem);

        client_fd = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
        if (client_fd < 0) {
            sem_post(&client_sem);
            continue;
        }

        // 创建子进程处理请求
        if (fork() == 0) {
            close(server_fd);
            handle_request(client_fd);
            close(client_fd);
            exit(EXIT_SUCCESS);
        }
        close(client_fd);
        // 释放信号量
        sem_post(&client_sem);
    }
}

void print_usage(const char *prog) {
    printf("Usage: %s [OPTIONS]\n", prog);
    printf("Options:\n");
    printf("  -p, --port PORT       HTTP server port (default: %d)\n", DEFAULT_PORT);
    printf("  -m, --sleep-port PORT UDP port for shutdown (default: 9999)\n");
    printf("  -s, --sleep-msg MSG  Shutdown message (default: shutdown)\n");
    printf("  -c, --code-seed PASS Code seed for generating access codes\n");
    printf("  -h, --help           Show this help message\n");
    printf("\n");
    printf("Authentication:\n");
    printf("  When -c is set, visit / to get a one-time access code\n");
    printf("  Use this code in /wake and /sleep requests\n");
    printf("  Each code can only be used once\n");
    printf("\n");
    printf("Fixed API paths:\n");
    printf("  /wake   - Wake-on-LAN\n");
    printf("  /sleep  - Shutdown broadcast\n");
}

int main(int argc, char *argv[]) {
    int opt;

    static struct option long_options[] = {
        {"port", required_argument, 0, 'p'},
        {"sleep-port", required_argument, 0, 'm'},
        {"sleep-msg", required_argument, 0, 's'},
        {"code-seed", required_argument, 0, 'c'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "p:m:s:c:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'p':
                config.port = atoi(optarg);
                break;
            case 'm':
                config.sleep_port = atoi(optarg);
                break;
            case 's':
                strncpy(config.sleep_msg, optarg, sizeof(config.sleep_msg) - 1);
                break;
            case 'c':
                strncpy(config.password_seed, optarg, sizeof(config.password_seed) - 1);
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    start_server();
    return 0;
}
