# !/usr/bin/env python3
"""
SYN Proxy测试 - 发送方h1
实现TCP客户端，发送正常连接和SYN包，并捕获SYN+ACK响应
"""

import socket
import struct
import time
import threading
from datetime import datetime
from scapy.all import *


class TCPClient:
    def __init__(self, target_host='10.0.0.2', target_port=8888):
        self.target_host = target_host
        self.target_port = target_port
        self.normal_connections = 0
        self.syn_packets_sent = 0
        self.syn_ack_packets_received = 0
        self.timestamp = int(time.time() * 1000)

    def normal_tcp_connection(self, connection_id):
        """建立正常TCP连接"""
        try:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] 开始正常TCP连接 #{connection_id}")

            # 创建socket
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(5.0)

            # 建立连接
            start_time = time.time()
            client_socket.connect((self.target_host, self.target_port))
            connect_time = (time.time() - start_time) * 1000

            print(
                f"[{datetime.now().strftime('%H:%M:%S')}] 连接 #{connection_id} 建立成功 (耗时: {connect_time:.2f}ms)")

            # 发送数据
            message = f"正常TCP连接消息 #{connection_id} from h1"
            client_socket.send(message.encode('utf-8'))

            # 接收响应
            response = client_socket.recv(1024)
            print(f"[{datetime.now().strftime('%H:%M:%S')}] 收到服务器响应: {response.decode('utf-8')}")

            # 关闭连接
            client_socket.close()
            print(f"[{datetime.now().strftime('%H:%M:%S')}] 连接 #{connection_id} 正常关闭")

        except socket.timeout:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] 连接 #{connection_id} 超时")
        except ConnectionRefusedError:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] 连接 #{connection_id} 被拒绝")
        except Exception as e:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] 连接 #{connection_id} 失败: {e}")

    def start_sniff(self):
        # 设置嗅探器来捕获响应包
        def packet_handler(pkt):
            print('received paaaaacket', pkt)
            print(pkt[IP])
            print(pkt[TCP])
            if (pkt.haslayer(TCP) and
                    pkt[TCP].flags == 0x12 and  # SYN+ACK
                    pkt[IP].src == self.target_host):
                self.syn_ack_packets_received += 1
                print(f"[{datetime.now().strftime('%H:%M:%S')}] *** 捕获到SYN+ACK包 #{packet_id} ***")
                print(f"    源IP: {pkt[IP].src}:{pkt[TCP].sport}")
                print(f"    目标IP: {pkt[IP].dst}:{pkt[TCP].dport}")
                print(f"    序列号: {pkt[TCP].seq}, 确认号: {pkt[TCP].ack}")
                print(f"    TCP标志位: {pkt[TCP].flags}")
                print(f"    窗口大小: {pkt[TCP].window}")

        def sniff_packet():
            # 捕获响应包（超时3秒）
            print(f"[{datetime.now().strftime('%H:%M:%S')}] 正在监听SYN+ACK响应...")
            sniff(filter=f"tcp and host {self.target_host}",
                  prn=packet_handler,
                  timeout=10,
                  count=100)

        thread = threading.Thread(target=sniff_packet)
        thread.start()

    def send_syn_and_capture_response(self, packet_id):
        """发送SYN包并捕获SYN+ACK响应"""
        # try:
        if 1 == 1:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] 发送SYN包 #{packet_id}")

            self.timestamp += 1000
            ts_val = self.timestamp
            ts_ecr = 0
            print(ts_val)
            ts_option = (b'\x01' b'\x08' + struct.pack('>QQ', ts_val, ts_ecr))
            # 构造SYN包
            src_port = 10000 + packet_id
            ip = IP(dst=self.target_host)
            tcp = TCP(dport=self.target_port, sport=src_port, flags='S', seq=packet_id * 1000)
            tcp.option = [ts_option]

            # 发送SYN包并等待响应
            print(f"[{datetime.now().strftime('%H:%M:%S')}] SYN包 #{packet_id} 已发送 (源端口: {src_port})")

            # 发送SYN包
            ansed = send(ip / tcp, verbose=0)
            if ansed:
                for sent, received in ansed:
                    if received.haslayer(TCP) and received[TCP].flags==0x12:
                        print('receive', received)
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] *** 捕获到SYN+ACK包 #{packet_id} ***")
                        print(f"    源IP: {received[IP].src}:{received[TCP].sport}")
                        print(f"    目标IP: {received[IP].dst}:{received[TCP].dport}")
                        print(f"    序列号: {received[TCP].seq}, 确认号: {received[TCP].ack}")
                        print(f"    TCP标志位: {received[TCP].flags}")
                        print(f"    窗口大小: {received[TCP].window}")
                        self.syn_ack_packets_received += 1
            self.syn_packets_sent += 1

            # if self.syn_ack_packets_received == 0:
            #     print(f"[{datetime.now().strftime('%H:%M:%S')}] SYN包 #{packet_id} 未收到响应")

        # except Exception as e:
        #     print(f"[{datetime.now().strftime('%H:%M:%S')}] SYN包 #{packet_id} 处理失败: {e}")

    def normal_test(self):
        # 测试1: 正常TCP连接
        print("\n--- 测试1: 正常TCP连接 ---")
        global normal_threads
        normal_threads = []
        for i in range(2):
            thread = threading.Thread(
                target=self.normal_tcp_connection,
                args=(i + 1,)
            )
            normal_threads.append(thread)
            thread.start()
            time.sleep(1)

        for thread in normal_threads:
            thread.join()

    def syn_test(self):
        # 测试2: 发送SYN包并捕获SYN+ACK响应
        print("\n--- 测试2: SYN包发送与SYN+ACK捕获 ---")
        # self.start_sniff()
        syn_threads = []
        for i in range(3):
            thread = threading.Thread(
                target=self.send_syn_and_capture_response,
                args=(i + 1,)
            )
            syn_threads.append(thread)
            thread.start()
            time.sleep(1)

        for thread in syn_threads:
            thread.join()

    def run_tests(self):
        """运行测试序列"""
        print("=" * 60)
        print("SDN SYN Proxy测试 - 完整包捕获版本")
        print(f"目标服务器: {self.target_host}:{self.target_port}")
        print("=" * 60)

        # self.normal_test()

        self.syn_test()

        # 输出测试统计
        print("\n" + "=" * 60)
        print("测试完成统计:")
        print(f"正常TCP连接完成: {len(normal_threads)}")
        print(f"单独SYN包发送: {self.syn_packets_sent}")
        print(f"捕获到的SYN+ACK包: {self.syn_ack_packets_received}")
        print("=" * 60)


def main():
    # client = TCPClient(target_host='10.0.0.2', target_port=8888)
    client = TCPClient(target_host='0.0.0.0', target_port=8888)
    client.run_tests()


if __name__ == "__main__":
    main()