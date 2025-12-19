#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_ARP = 0x0806;
const bit<8> PROTO_TCP = 6;
const bit<6> TCP_SYN = 0x02;
const bit<6> TCP_ACK = 0x10;
const bit<6> TCP_SYN_ACK = 0x12;
const bit<6> TCP_PSH_ACK = 0x18;
const bit<6> TCP_FIN = 0x01;

// 寄存器配置
#define REGISTER_SIZE (bit<32>)65536
#define MAX_SEQ_OFFSET (bit<32>)0xFFFFFFFF

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header arp_t {
    bit<16> hw_type;
    bit<16> proto_type;
    bit<8> hw_addr_len;
    bit<8> proto_addr_len;
    bit<16> opcode;
    bit<48> sender_hw_addr;
    bit<32> sender_proto_addr;
    bit<48> target_hw_addr;
    bit<32> target_proto_addr;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}


header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;

    // tcp_option_t tcp_option;
}

struct metadata {
    bit<16>  reg_index;
    bit<16>  reg_rev_index;
    bit<32>  proxy_isn;
    bit<1>   direction;  // 0: client->server, 1: server->client
    bit<32> seq_offset;
    bit<32> ack_offset;
    bit<16> tcpSegLen;
}

struct headers {
    ethernet_t   ethernet;
    arp_t        arp;
    ipv4_t       ipv4;
    tcp_t        tcp;
}

// 连接状态寄存器
register<bit<32>>(REGISTER_SIZE) client_ip_reg;
register<bit<16>>(REGISTER_SIZE) client_port_reg;
register<bit<32>>(REGISTER_SIZE) server_ip_reg;
register<bit<16>>(REGISTER_SIZE) server_port_reg;
register<bit<32>>(REGISTER_SIZE) client_isn_reg;
register<bit<32>>(REGISTER_SIZE) proxy_isn_reg;
register<bit<32>>(REGISTER_SIZE) seq_offset_reg;
register<bit<32>>(REGISTER_SIZE) ack_offset_reg;
register<bit<8>>(REGISTER_SIZE) conn_state_reg;
// register<bit<48>>(REGISTER_SIZE) timestamp_reg;

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_ARP: parse_arp;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
        //transition select(hdr.tcp.dataOffset) {
        //    5: accept;
        //    10: parse_tcp_option;
        //    default: accept;
        //}
    }

    //state parse_tcp_option {
     //   packet.extract(hdr.tcp_option);
    //    transition accept;
    //}
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action calc_reg_index() {
        // 基于四元组计算哈希索引
        hash(meta.reg_index, HashAlgorithm.crc32, (bit<32>)0, {hdr.ipv4.srcAddr,
                                                           hdr.ipv4.dstAddr,
                                                           hdr.tcp.srcPort,
                                                           hdr.tcp.dstPort,
                                                           hdr.ipv4.protocol},
                                                           REGISTER_SIZE);
        //bit<128> hash_input = (bit<128>)hdr.ipv4.srcAddr << 96 |
        //                  (bit<128>)hdr.ipv4.dstAddr << 64 |
        //                   (bit<128>)hdr.tcp.srcPort << 48 |
        //                   (bit<128>)hdr.tcp.dstPort << 32;
        //meta.reg_index = (bit<10>)(hash_input % REGISTER_SIZE);
    }

    // if direction is from server to client
    action calc_reg_index_rev() {
        hash(meta.reg_rev_index, HashAlgorithm.crc32, (bit<32>)0, {hdr.ipv4.dstAddr,
                                                           hdr.ipv4.srcAddr,
                                                           hdr.tcp.dstPort,
                                                           hdr.tcp.srcPort,
                                                           hdr.ipv4.protocol},
                                                           REGISTER_SIZE);
    }

    action handle_client_syn() {
        calc_reg_index();

        bit<8> current_state;
        conn_state_reg.read(current_state, (bit<32>)meta.reg_index);

        if (current_state == 0) { // 空闲槽位
            // 保存原始连接信息
            client_ip_reg.write((bit<32>)meta.reg_index, hdr.ipv4.srcAddr);
            client_port_reg.write((bit<32>)meta.reg_index, hdr.tcp.srcPort);
            server_ip_reg.write((bit<32>)meta.reg_index, hdr.ipv4.dstAddr);
            server_port_reg.write((bit<32>)meta.reg_index, hdr.tcp.dstPort);
            client_isn_reg.write((bit<32>)meta.reg_index, hdr.tcp.seqNo);

            // 生成代理序列号和偏移量
            // there is no real random function, should use hash function
            // meta.proxy_isn = (bit<32>)random(0, MAX_SEQ_OFFSET);
            hash(meta.proxy_isn, HashAlgorithm.crc32, (bit<32>)0, {hdr.ipv4.srcAddr,
                                                           hdr.ipv4.dstAddr,
                                                           hdr.tcp.srcPort,
                                                           hdr.tcp.dstPort,
                                                           hdr.ipv4.protocol},
                                                           MAX_SEQ_OFFSET);
            proxy_isn_reg.write((bit<32>)meta.reg_index, meta.proxy_isn);

            // 计算序列号偏移量
            // 客户端到服务器: seq_offset = proxy_isn - client_isn
            bit<32> client_isn;
            client_isn_reg.read(client_isn, (bit<32>)meta.reg_index);
            // meta.seq_offset = meta.proxy_isn - client_isn;
            // seq_offset_reg.write((bit<32>)meta.reg_index, meta.seq_offset);

            // 设置连接状态
            conn_state_reg.write((bit<32>)meta.reg_index, 1); // 等待客户端ACK

            // 发送SYN-ACK给客户端
            // send_syn_ack_to_client();
            bit<32> server_ip;
            bit<16> server_port;

            server_ip_reg.read(server_ip, (bit<32>)meta.reg_index);
            server_port_reg.read(server_port, (bit<32>)meta.reg_index);

            bit<48> srcMac = hdr.ethernet.srcAddr;
            hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
            hdr.ethernet.dstAddr = srcMac;
            hdr.ipv4.dstAddr = hdr.ipv4.srcAddr;
            hdr.ipv4.srcAddr = server_ip;
            hdr.tcp.dstPort = hdr.tcp.srcPort;
            hdr.tcp.srcPort = server_port;
            hdr.tcp.ackNo = hdr.tcp.seqNo + 1;
            hdr.tcp.seqNo = meta.proxy_isn;
            hdr.tcp.ctrl = TCP_SYN_ACK;

            // if (hdr.tcp.tcp_option.tcp_ts.ts_ecr != 0) {
            //    hdr.tcp.tcp_option.tcp_ts.ts_ecr = hdr.tcp.tcp_option.tcp_ts.ts_val;
            // }
            // hdr.tcp.tcp_option.tcp_ts.ts_val = hdr.tcp.tcp_option.tcp_ts.ts_val + 50;

            meta.tcpSegLen = (bit<16>)(hdr.ipv4.totalLen - (bit<16>)hdr.ipv4.ihl * 4);
            // hdr.tcp.checksum = 0;

            standard_metadata.egress_spec = standard_metadata.ingress_port; // 客户端端口
        }
    }
    action none() {

    }
    table debugger {
        key = {
            meta.reg_index: exact;
            hdr.tcp.dstPort: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.tcp.seqNo: exact;
            hdr.tcp.srcPort: exact;
            hdr.ipv4.srcAddr: exact;
            hdr.tcp.ctrl: exact;
        }
        actions = {
            none;
        }
        default_action = none;
    }

    action verify_client_ack() {
        calc_reg_index();

        bit<8> current_state;
        bit<32> stored_proxy_isn;

        conn_state_reg.read(current_state, (bit<32>)meta.reg_index);
        proxy_isn_reg.read(stored_proxy_isn, (bit<32>)meta.reg_index);

        if (current_state == 1) {
            bit<32> expected_ack = stored_proxy_isn + 1;

            if (hdr.tcp.ackNo == expected_ack) {
                // ACK验证通过，与服务器建立连接
                conn_state_reg.write((bit<32>)meta.reg_index, 2); // 等待服务器SYN-ACK
                // maybe no need to +1
                // proxy_isn_reg.write((bit<32>)meta.reg_index, expected_ack);

                // initiate_server_connection();
                bit<32> client_ip;
                bit<16> client_port;
                bit<32> server_ip;
                bit<16> server_port;
                bit<32> client_isn;

                client_ip_reg.read(client_ip, (bit<32>)meta.reg_index);
                client_port_reg.read(client_port, (bit<32>)meta.reg_index);
                server_ip_reg.read(server_ip, (bit<32>)meta.reg_index);
                server_port_reg.read(server_port, (bit<32>)meta.reg_index);
                client_isn_reg.read(client_isn, (bit<32>)meta.reg_index);

                hdr.ipv4.srcAddr = client_ip;
                hdr.ipv4.dstAddr = server_ip;
                hdr.tcp.srcPort = client_port;
                hdr.tcp.dstPort = server_port;
                hdr.tcp.seqNo = client_isn;
                hdr.tcp.ackNo = 0;
                hdr.tcp.ctrl = TCP_SYN;

                // standard_metadata.egress_spec = 2; // 服务器端口

            } else {
                mark_to_drop(standard_metadata);
            }
        }
    }

    action handle_server_syn_ack() {
        calc_reg_index_rev();

        bit<8> current_state;
        conn_state_reg.read(current_state,(bit<32>) meta.reg_rev_index);

        if (current_state == 2) {
            // 计算ACK偏移量
            // 服务器到客户端: ack_offset = proxy_isn - client_isn
            bit<32> client_isn;
            bit<32> proxy_isn;

            // client_isn_reg.read(client_isn, (bit<32>)meta.reg_rev_index);
            proxy_isn_reg.read(proxy_isn, (bit<32>)meta.reg_rev_index);
            meta.ack_offset = proxy_isn - hdr.tcp.seqNo;
            ack_offset_reg.write((bit<32>)meta.reg_rev_index, meta.ack_offset);

            // 发送ACK给服务器完成握手
            // send_ack_to_server();
            bit<32> client_ip;
            bit<16> client_port;
            bit<32> server_ip;
            bit<16> server_port;

            client_ip_reg.read(client_ip, (bit<32>)meta.reg_rev_index);
            client_port_reg.read(client_port, (bit<32>)meta.reg_rev_index);
            server_ip_reg.read(server_ip, (bit<32>)meta.reg_rev_index);
            server_port_reg.read(server_port, (bit<32>)meta.reg_rev_index);

            bit<48> srcMac = hdr.ethernet.srcAddr;
            hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
            hdr.ethernet.dstAddr = srcMac;
            hdr.ipv4.srcAddr = client_ip;
            hdr.ipv4.dstAddr = server_ip;
            hdr.tcp.srcPort = client_port;
            hdr.tcp.dstPort = server_port;
            hdr.tcp.ctrl = TCP_ACK;
            bit<32> tmp_ack = hdr.tcp.ackNo;
            hdr.tcp.ackNo = hdr.tcp.seqNo + 1;
            hdr.tcp.seqNo = tmp_ack;

            // standard_metadata.egress_spec = 2; // 服务器端口

            // 设置连接为已建立状态
            conn_state_reg.write((bit<32>)meta.reg_rev_index, 3);
        }
    }
    // todo forward pakcet with an offset only when the stream is from server to client
    // 客户端到服务器的数据包处理（应用序列号偏移）
    action forward_client_to_server() {
        calc_reg_index();

        bit<8> current_state;
        bit<32> seq_offset;

        conn_state_reg.read(current_state, (bit<32>)meta.reg_index);
        seq_offset_reg.read(seq_offset, (bit<32>)meta.reg_index);

        if (current_state == 3) {
            // 应用序列号偏移
            hdr.tcp.seqNo = hdr.tcp.seqNo + seq_offset;

            standard_metadata.egress_spec = 2; // 服务器端口
        }
    }

    // state 3: offset server seq or client ackSeq
    action forward_packet_with_seq_offset() {
        calc_reg_index();
        calc_reg_index_rev();

        bit<8> rev_state;
        bit<8> current_state;
        conn_state_reg.read(current_state, (bit<32>)meta.reg_index);
        conn_state_reg.read(rev_state, (bit<32>)meta.reg_rev_index);
        bit<32> ack_offset;
        if (current_state == 3) {
            ack_offset_reg.read(ack_offset, (bit<32>)meta.reg_index);
            hdr.tcp.ackNo = hdr.tcp.ackNo - ack_offset;
        } else if (rev_state == 3) {
            ack_offset_reg.read(ack_offset, (bit<32>)meta.reg_rev_index);
            hdr.tcp.seqNo = hdr.tcp.seqNo + ack_offset;
        }
    }

     action send_arp_reply(bit<48> target_mac) {
        /* 交换源和目标MAC地址 */
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = target_mac;

        /* 设置ARP响应 */
        hdr.arp.opcode = 0x0002; // ARP回复
        hdr.arp.target_hw_addr = hdr.arp.sender_hw_addr;
        bit<32> target_ip;
        target_ip = hdr.arp.target_proto_addr;
        hdr.arp.target_proto_addr = hdr.arp.sender_proto_addr;
        hdr.arp.sender_hw_addr = target_mac;
        hdr.arp.sender_proto_addr = target_ip;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    table arp_table {
        key = {
            hdr.arp.target_proto_addr: exact;
        }
        actions = {
            send_arp_reply;
            drop;
        }
        default_action = drop;
    }

    action set_port_forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    table mac_port_table {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            set_port_forward;
            drop;
        }
        default_action = drop;
    }

    apply {
        if (hdr.arp.isValid() && hdr.arp.opcode == 0x0001) {
            arp_table.apply();
            standard_metadata.egress_spec = standard_metadata.ingress_port;
        }
        // todo in furture, this should be surrounded with threshold trigger
        else if (hdr.ipv4.isValid() && hdr.tcp.isValid()) {
            // 根据数据包方向设置元数据
            if (standard_metadata.ingress_port == 1) { // 来自客户端
                meta.direction = 0;
            } else if (standard_metadata.ingress_port == 2) { // 来自服务器
                meta.direction = 1;
            }

            // SYN报文处理
            if (hdr.tcp.ctrl == TCP_SYN) {
                handle_client_syn();
            }
            // 客户端ACK验证 and data transport
            else if (hdr.tcp.ctrl == TCP_ACK) {
                // todo replace meta direction and data transfer in verify client ack function
                verify_client_ack();
                debugger.apply();
                forward_packet_with_seq_offset();
                mac_port_table.apply();
            }
            else if (hdr.tcp.ctrl == TCP_PSH_ACK) {
                forward_packet_with_seq_offset();
                mac_port_table.apply();
            }
            // 服务器SYN-ACK处理
            else if (hdr.tcp.ctrl == TCP_SYN_ACK) {
                handle_server_syn_ack();
                mac_port_table.apply();
            }
        }
            // todo same level with SYN proxy, add rate limitor in data transfer

        // todo if normal without threshold, using direct transfer

    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);

        //update_checksum_with_payload(
          //          hdr.tcp.isValid(),
            //        { hdr.ipv4.srcAddr,
              //        hdr.ipv4.dstAddr,
                //      8w0,
                  //    8w6,
                    //  meta.tcpSegLen,
                    //},
                    //hdr.tcp.checksum,
                    //HashAlgorithm.csum16);


    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        // if (hdr.tcp.isValid()) {
        packet.emit(hdr.tcp);
        // }
        // packet.emit(hdr.tcp_option);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;