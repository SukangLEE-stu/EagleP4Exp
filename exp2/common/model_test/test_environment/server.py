# !/usr/bin/env python3

from scapy.all import *
from collections import defaultdict
import threading
import time
import random


class ScapyTCPProxy:
    def __init__(self, interface=None, listen_port=8888):
        self.interface = interface
        self.listen_port = listen_port
        self.running = False
        self.connections = defaultdict(dict)
        self.proxy_ip = "10.0.0.2"  # H2的IP地址

    def handle_packet(self, packet):
        """处理接收到的数据包"""
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return

        ip_layer = packet[IP]
        tcp_layer = packet[TCP]

        # 只处理目标端口为8888的TCP包
        if tcp_layer.dport != self.listen_port:
            return

        src_ip = ip_layer.src
        src_port = tcp_layer.sport
        dst_ip = ip_layer.dst
        dst_port = tcp_layer.dport
        flags = tcp_layer.flags
        seq_num = tcp_layer.seq
        ack_num = tcp_layer.ack

        connection_key = f"{src_ip}:{src_port}"

        print(f"H2: 收到来自 {src_ip}:{src_port} 的包")
        print(f"    目标端口: {dst_port}, 序列号: {seq_num}, 标志位: {flags}")

        # 处理SYN包
        if flags == "S":  # SYN标志
            print(f"H2: 检测到SYN包，发送SYN+ACK响应")

            # 生成代理序列号和确认号
            proxy_seq_num = random.randint(1000000000, 4294967295)
            proxy_ack_num = seq_num + 1

            # 创建并发送SYN+ACK包
            syn_ack_packet = IP(src=dst_ip, dst=src_ip) / \
                             TCP(sport=dst_port, dport=src_port,
                                 seq=proxy_seq_num, ack=proxy_ack_num,
                                 flags="SA")  # SYN + ACK

            send(syn_ack_packet, verbose=0)
            print(f"H2: 已发送SYN+ACK到 {src_ip}:{src_port}")

            # 记录连接信息
            self.connections[connection_key] = {
                'client_seq': seq_num,
                'proxy_seq': proxy_seq_num + 1,
                'state': 'SYN_RECEIVED'
            }

        # 处理ACK包（完成三次握手）
        elif flags == "A" and connection_key in self.connections:
            conn_info = self.connections[connection_key]
            if conn_info['state'] == 'SYN_RECEIVED':
                print(f"H2: 收到ACK包，TCP连接建立完成")
                conn_info['state'] = 'ESTABLISHED'


        # 处理带数据的包（PSH标志）
        elif flags in ["PA", "A"] and packet.haslayer(Raw):
            conn_info = self.connections[connection_key]
            if connection_key in self.connections:
                payload = packet[Raw].load
                print(f"H2: 收到数据: {payload.decode('utf-8', errors='ignore')}")

                # 发送ACK确认
                if conn_info['state'] == 'ESTABLISHED':
                    conn_info['client_seq'] += len(payload)
                    ack_packet = IP(src=dst_ip, dst=src_ip) / \
                                 TCP(sport=dst_port, dport=src_port,
                                     seq=conn_info['proxy_seq'],
                                     ack=conn_info['client_seq'],
                                     flags="A")

                    send(ack_packet, verbose=0)
                    print(f"H2: 已发送ACK确认")

                    # 处理应用层逻辑
                    ## self.handle_application_data(src_ip, src_port, payload, conn_info)

    def handle_application_data(self, src_ip, src_port, payload, conn_info):
        """处理应用层数据"""
        try:
            message = payload.decode('utf-8')
            print(f"H2: 应用层消息: {message}")

            # 这里可以添加业务逻辑处理
            response_msg = f"已收到您的消息: {message}"

            # 发送响应数据
            response_packet = IP(src=dst_ip, dst=src_ip) / \
                              TCP(sport=dst_port, dport=src_port,
                                  seq=conn_info['proxy_seq'],
                                  ack=conn_info['client_seq'] + len(payload),
                                  flags="PA") / Raw(load=response_msg.encode('utf-8'))

            send(response_packet, verbose=0)
            print(f"H2: 已发送响应: {response_msg}")

        except Exception as e:
            print(f"H2: 处理应用数据时出错: {e}")

    def start_proxy(self):
        """启动TCP代理"""
        try:
            print(f"H2: Scapy TCP代理启动在端口 {self.listen_port}")
            print("H2: 等待TCP包...")

            # 设置过滤器：只监听目标端口为8888的TCP包
            filter_str = f"tcp dst port {self.listen_port}"

            self.running = True

            # 开始嗅探
            sniff(filter=filter_str,
                  prn=self.handle_packet,
                  iface=self.interface,
                  stop_filter=lambda x: not self.running)

        except Exception as e:
            print(f"H2: 启动代理失败: {e}")

    def stop_proxy(self):
        """停止代理"""
        self.running = False
        print("H2: TCP代理已停止")


def main():
    # 根据实际接口名称修改
    proxy = ScapyTCPProxy(interface="eth0", listen_port=8888)

    try:
        proxy.start_proxy()
    except KeyboardInterrupt:
        print("\nH2: 正在停止代理...")
        proxy.stop_proxy()


if __name__ == '__main__':
    main()