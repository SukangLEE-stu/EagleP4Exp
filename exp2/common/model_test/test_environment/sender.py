# !/usr/bin/env python3
"""
SYN Proxy测试 - 修复版h1发送端
解决无法收到SYN+ACK回复的问题 - 使用sr1同步等待响应
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
        self.client = {}

    def normal_tcp_connection(self, connection_id):
        """建立正常TCP连接"""
        try:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] 开始正常TCP连接 #{connection_id}")

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(5.0)

            start_time = time.time()
            client_socket.connect((self.target_host, self.target_port))
            connect_time = (time.time() - start_time) * 1000

            print(
                f"[{datetime.now().strftime('%H:%M:%S')}] 连接 #{connection_id} 建立成功 (耗时: {connect_time:.2f}ms)")

            message = f"正常TCP连接消息 #{connection_id} from h1"
            client_socket.send(message.encode('utf-8'))

            response = client_socket.recv(1024)
            print(f"[{datetime.now().strftime('%H:%M:%S')}] 收到服务器响应: {response.decode('utf-8')}")

            client_socket.close()
            print(f"[{datetime.now().strftime('%H:%M:%S')}] 连接 #{connection_id} 正常关闭")

        except Exception as e:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] 连接 #{connection_id} 失败: {e}")

    def send_syn_and_capture_response(self, packet_id):
        """发送SYN包并同步等待SYN+ACK响应"""
        try:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] 发送SYN包 #{packet_id}")

            # 使用递增的源端口避免冲突
            src_port = 10000 + packet_id

            # 构造SYN包 - 简化版本，不使用复杂的时间戳选项
            ip = IP(dst=self.target_host)
            tcp = TCP(dport=self.target_port, sport=src_port, flags='S', seq=packet_id * 1000)

            # 使用sr1同步发送并等待单个响应
            response = sr1(ip / tcp, timeout=3, verbose=0)

            if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
                self.syn_ack_packets_received += 1
                print(f"[{datetime.now().strftime('%H:%M:%S')}] *** 成功捕获SYN+ACK包 #{packet_id} ***")
                print(f"    源: {response[IP].src}:{response[TCP].sport}")
                print(f"    目标: {response[IP].dst}:{response[TCP].dport}")
                print(f"    序列号: {response[TCP].seq}, 确认号: {response[TCP].ack}")
                print(f"    标志位: SYN={response[TCP].flags & 0x02 != 0}, ACK={response[TCP].flags & 0x10 != 0}")
                print(f"    窗口: {response[TCP].window}")

                print("\n\nreplying with ACK")
                time.sleep(3)
                self.send_ack_response(response, packet_id)

            else:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] SYN包 #{packet_id} 未收到响应")

            self.syn_packets_sent += 1

        except Exception as e:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] SYN包 #{packet_id} 处理失败: {e}")

    def send_ack_response(self, syn_ack_packet, packet_id):
        """当收到SYN+ACK时，返回ACK包完成三次握手"""
        try:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] 发送ACK包 #{packet_id}")

            # 从SYN+ACK包中提取必要信息
            server_ip = syn_ack_packet[IP].src
            server_port = syn_ack_packet[TCP].sport
            client_ip = syn_ack_packet[IP].dst
            client_port = syn_ack_packet[TCP].dport
            server_seq = syn_ack_packet[TCP].seq
            server_ack = syn_ack_packet[TCP].ack

            # 构造ACK包
            ack_ip = IP(src=client_ip, dst=server_ip)
            ack_tcp = TCP(sport=client_port, dport=server_port, flags='A',
                          seq=server_ack, ack=server_seq + 1)

            # 发送ACK包
            send(ack_ip / ack_tcp, verbose=0)

            # self.ack_packets_sent += 1
            print(f"[{datetime.now().strftime('%H:%M:%S')}] *** ACK包 #{packet_id} 发送成功 ***")
            print(f"    序列号: {server_ack}, 确认号: {server_seq + 1}")
            print(f"    完成TCP三次握手过程")

            # 3秒后发送TCP数据包
            # threading.Timer(3.0, self.send_tcp_data,
            #                 args=(packet_id, server_ip, server_port, client_ip, client_port, server_ack,
            #                       server_seq + 1)).start()
            self.client[packet_id] = {
                'server_ip': server_ip,
                'server_port': server_port,
                'client_ip': client_ip,
                'client_port': client_port,
                'server_ack': server_ack,
                'server_seq': server_seq + 1,
            }

            time.sleep(3)
            self.send_tcp_data_with_timer(packet_id)

        except Exception as e:
            print('error happens', e)

    def send_tcp_data_with_timer(self, packet_id):
        times = 0
        threshold = 100
        while times < threshold:
            lens = self.send_tcp_data(packet_id,
                               self.client[packet_id]['server_ip'],
                               self.client[packet_id]['server_port'],
                               self.client[packet_id]['client_ip'],
                               self.client[packet_id]['client_port'],
                               self.client[packet_id]['server_ack'],
                               self.client[packet_id]['server_seq'])
            self.client[packet_id]['server_ack'] += lens
            time.sleep(3)


    def send_tcp_data(self, packet_id, server_ip, server_port, client_ip, client_port, seq, ack):
        """发送TCP数据包"""
        try:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] 发送TCP数据包 #{packet_id}")

            # 构造TCP数据包
            data_ip = IP(src=client_ip, dst=server_ip)
            data_tcp = TCP(sport=client_port, dport=server_port, flags='PA',
                           seq=seq, ack=ack)
            data_payload = f"TCP数据包 #{packet_id} 在ACK后3秒发送".encode('utf-8')

            # 发送TCP数据包
            send(data_ip / data_tcp / data_payload, verbose=0)

            print(f"[{datetime.now().strftime('%H:%M:%S')}] &zwnj;*** TCP数据包 #{packet_id} 发送成功 ***&zwnj;")

            return len(data_payload)
        except Exception as e:
            print(f"发送TCP数据包失败: {e}")

    def test_normal(self):
        # 测试1: 正常TCP连接
        print("\n--- 测试1: 正常TCP连接 ---")
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

    def test_syn(self):
        # 测试2: 发送SYN包并捕获响应
        print("\n--- 测试2: SYN包发送与响应捕获 ---")
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
        print("SDN SYN Proxy测试 - 同步等待修复版")
        print("=" * 60)

        # self.test_normal()
        self.test_syn()

        # 输出测试统计
        print("\n" + "=" * 60)
        print("测试完成统计:")
        # print(f"正常TCP连接完成: {len(normal_threads)}")
        print(f"单独SYN包发送: {self.syn_packets_sent}")
        print(f"捕获到的SYN+ACK包: {self.syn_ack_packets_received}")
        print("=" * 60)


def main():
    # client = TCPClient(target_host='127.0.0.1', target_port=8888)
    client = TCPClient(target_host='10.0.1.2', target_port=8888)
    client.run_tests()


if __name__ == "__main__":
    main()