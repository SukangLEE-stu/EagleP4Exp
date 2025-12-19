# !/usr/bin/env python3
"""
SYN Proxy测试 - 接收方h2
实现TCP服务器，接收正常连接并记录SYN包
"""

import socket
import threading
import time
from datetime import datetime


class TCPServer:
    def __init__(self, host='127.0.0.1', port=8888):
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        self.connection_count = 0
        self.syn_count = 0

    def start_server(self):
        """启动TCP服务器"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except OSError as e:
            print(f"创建socket失败: {e}")
            return

        try:
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)  # 设置超时以便能够检查运行状态
        except OSError as e:
            print(f"绑定端口失败: {e}")
            return

        self.running = True
        print(f"服务器启动在 {self.host}:{self.port}")
        print("等待连接...")

        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                self.connection_count += 1
                print(
                    f"\n[{datetime.now().strftime('%H:%M:%S')}] 新连接 #{self.connection_count} 来自 {client_address}")

                # 为每个客户端创建新线程
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()

            except socket.timeout:
                continue
            except OSError as e:
                if self.running:
                    print(f"接受连接错误: {e}")
                break

    def handle_client(self, client_socket, client_address):
        """处理客户端连接"""
        try:
            # 接收客户端数据
            data = client_socket.recv(1024)
            if data:
                print(f"来自 {client_address} 的数据: {data.decode('utf-8', errors='ignore')}")

                # 发送响应
                response = f"服务器响应: 收到你的消息 at {datetime.now().strftime('%H:%M:%S')}"
                client_socket.send(response.encode('utf-8'))

            # 保持连接一段时间以模拟正常通信
            time.sleep(2)

        except Exception as e:
            print(f"处理客户端 {client_address} 时出错: {e}")
        finally:
            client_socket.close()
            print(f"连接 {client_address} 已关闭")

    def stop_server(self):
        """停止服务器"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        print("服务器已停止")


def main():
    server = TCPServer(host='10.0.1.2', port=8888)
    # server = TCPServer()

    try:
        server.start_server()
    except KeyboardInterrupt:
        print("\n收到中断信号，正在停止服务器...")
    finally:
        server.stop_server()


if __name__ == "__main__":
    main()