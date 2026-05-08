package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("用法: shutdown_server <秘钥消息> [端口]")
		fmt.Println("示例: shutdown_server my-secret-key 9999")
		os.Exit(1)
	}

	secretMessage := os.Args[1]
	port := "9"
	if len(os.Args) >= 3 {
		port = os.Args[2]
	}

	fmt.Printf("Shutdown UDP Server 启动中...\n")
	fmt.Printf("监听端口: %s\n", port)
	fmt.Printf("秘钥消息: %s\n", secretMessage)

	addr, err := net.ResolveUDPAddr("udp", ":"+port)
	if err != nil {
		log.Fatalf("解析UDP地址失败: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("监听UDP端口失败: %v", err)
	}
	defer conn.Close()

	fmt.Printf("服务已启动，正在等待关机指令...\n")

	buffer := make([]byte, 1024)

	for {
		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("读取数据失败: %v", err)
			continue
		}

		receivedMessage := string(buffer[:n])
		fmt.Printf("收到来自 %s 的消息: %s\n", remoteAddr.IP, receivedMessage)

		if receivedMessage == secretMessage {
			fmt.Println("消息匹配! 正在执行关机...")
			shutdownSystem()
			break
		} else {
			fmt.Println("消息不匹配，忽略请求")
		}
	}
}

func shutdownSystem() {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("shutdown", "/s", "/t", "0")
	case "linux":
		cmd = exec.Command("shutdown", "-h", "now")
	case "darwin":
		cmd = exec.Command("shutdown", "-h", "now")
	default:
		log.Fatalf("不支持的操作系统: %s", runtime.GOOS)
	}

	if err := cmd.Run(); err != nil {
		log.Fatalf("执行关机命令失败: %v", err)
	}
}
