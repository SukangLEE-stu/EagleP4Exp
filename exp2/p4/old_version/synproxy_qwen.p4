#include <v1model.p4>

// ===== Constants =====
const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_ARP  = 0x0806;
const bit<16> ARP_REQUEST = 0x0001;
const bit<16> ARP_REPLY   = 0x0002;
const bit<8>  PROTO_TCP = 6;
const bit<6>  TCP_SYN = 0x02;
const bit<6>  TCP_ACK = 0x10;
const bit<6>  TCP_SYN_ACK = 0x12;

// ===== Headers =====
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header arp_t {
    bit<16> hw_type;
    bit<16> proto_type;
    bit<8>  hw_addr_len;
    bit<8>  proto_addr_len;
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
}

// ===== Metadata =====
struct metadata {
    bit<10>  reg_index;
    bit<32>  proxy_isn;
    bit<1>   direction;      // 0: client->proxy, 1: server->proxy
    bit<32>  seq_offset;
    bit<32>  ack_offset;
    bit<8>   do_action;      // 0:normal, 1:send server SYN, 2:send server ACK
    bit<16>  tcpSegLen;
    bit<32>  arp_ip;
    bit<48>  arp_mac;
}

struct headers {
    ethernet_t ethernet;
    arp_t      arp;
    ipv4_t     ipv4;
    tcp_t      tcp;
}

// ===== Registers =====
#define CONN_TABLE_SIZE 4096
#define ARP_TABLE_SIZE  1024

register<bit<32>>(CONN_TABLE_SIZE) client_ip_reg;
register<bit<16>>(CONN_TABLE_SIZE) client_port_reg;
register<bit<32>>(CONN_TABLE_SIZE) server_ip_reg;
register<bit<16>>(CONN_TABLE_SIZE) server_port_reg;
register<bit<32>>(CONN_TABLE_SIZE) client_isn_reg;
register<bit<32>>(CONN_TABLE_SIZE) proxy_isn_reg;
register<bit<32>>(CONN_TABLE_SIZE) seq_offset_reg;
register<bit<32>>(CONN_TABLE_SIZE) ack_offset_reg;
register<bit<8>>(CONN_TABLE_SIZE) conn_state_reg;

register<bit<48>>(ARP_TABLE_SIZE) arp_table;

const bit<32> SWITCH_IP = 32w0x0A00000A;   // 10.0.0.10
const bit<48> SWITCH_MAC = 48w0x000000000A0A; // 00:00:00:00:0a:0a

// ===== Parser =====
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_ARP:  parse_arp;
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
    }
}

// ===== Ingress Control =====
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action calc_arp_index(bit<32> ip) {
        meta.reg_index = (bit<10>)(ip & (ARP_TABLE_SIZE - 1));
    }

    action send_arp_reply(bit<48> target_mac, bit<32> target_ip) {
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = SWITCH_MAC;

        hdr.arp.opcode = ARP_REPLY;
        hdr.arp.target_hw_addr = hdr.arp.sender_hw_addr;
        hdr.arp.target_proto_addr = hdr.arp.sender_proto_addr;
        hdr.arp.sender_hw_addr = target_mac;
        hdr.arp.sender_proto_addr = target_ip;

        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    action learn_arp() {
        if (hdr.ipv4.isValid()) {
            calc_arp_index(hdr.ipv4.srcAddr);
            arp_table.write(meta.reg_index, hdr.ethernet.srcAddr);
        }
    }

    action lookup_arp_mac(bit<32> ip) {
        calc_arp_index(ip);
        arp_table.read(meta.arp_mac, meta.reg_index);
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    // --- Connection hash ---
    action calc_conn_index() {
        hash(meta.reg_index, HashAlgorithm.crc32, (bit<32>)0,
             {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort},
             CONN_TABLE_SIZE);
    }

    // --- Step 1: Client SYN ---
    action handle_client_syn() {
        calc_conn_index();

        bit<8> state;
        conn_state_reg.read(state, (bit<32>)meta.reg_index);
        if (state != 0) { drop(); return; }

        // Save connection info
        client_ip_reg.write((bit<32>)meta.reg_index, hdr.ipv4.srcAddr);
        client_port_reg.write((bit<32>)meta.reg_index, hdr.tcp.srcPort);
        server_ip_reg.write((bit<32>)meta.reg_index, hdr.ipv4.dstAddr);
        server_port_reg.write((bit<32>)meta.reg_index, hdr.tcp.dstPort);
        client_isn_reg.write((bit<32>)meta.reg_index, hdr.tcp.seqNo);

        // Generate proxy ISN
        hash(meta.proxy_isn, HashAlgorithm.crc32, (bit<32>)0,
             {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort},
             0xFFFFFFFF);
        proxy_isn_reg.write((bit<32>)meta.reg_index, meta.proxy_isn);

        // Compute seq offset
        bit<32> client_isn;
        client_isn_reg.read(client_isn, (bit<32>)meta.reg_index);
        meta.seq_offset = meta.proxy_isn - client_isn;
        seq_offset_reg.write((bit<32>)meta.reg_index, meta.seq_offset);

        conn_state_reg.write((bit<32>)meta.reg_index, 1);

        // Reply to client
        lookup_arp_mac(hdr.ipv4.srcAddr);
        if (meta.arp_mac == 0) { drop(); return; }

        hdr.ethernet.dstAddr = meta.arp_mac;
        hdr.ethernet.srcAddr = SWITCH_MAC;
        hdr.ipv4.dstAddr = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = server_ip_reg.read((bit<32>)meta.reg_index); // will be overwritten below
        bit<32> server_ip;
        server_ip_reg.read(server_ip, (bit<32>)meta.reg_index);
        hdr.ipv4.srcAddr = server_ip;

        hdr.tcp.dstPort = hdr.tcp.srcPort;
        bit<16> server_port;
        server_port_reg.read(server_port, (bit<32>)meta.reg_index);
        hdr.tcp.srcPort = server_port;

        hdr.tcp.ackNo = hdr.tcp.seqNo + 1;
        hdr.tcp.seqNo = meta.proxy_isn;
        hdr.tcp.ctrl = TCP_SYN_ACK;
        hdr.tcp.dataOffset = 5;

        standard_metadata.egress_spec = 1;
    }

    // --- Step 2: Client ACK ---
    action handle_client_ack() {
        calc_conn_index();

        bit<8> state;
        conn_state_reg.read(state, (bit<32>)meta.reg_index);
        if (state != 1) { drop(); return; }

        bit<32> proxy_isn;
        proxy_isn_reg.read(proxy_isn, (bit<32>)meta.reg_index);
        if (hdr.tcp.ackNo != proxy_isn + 1) { drop(); return; }

        meta.do_action = 1;
        recirculate(meta);
    }

    // --- Step 3: Send SYN to Server (via recirculate) ---
    action send_server_syn() {
        calc_conn_index();

        bit<32> cip; bit<32> sip;
        bit<16> cport; bit<16> sport;
        bit<32> cisn;

        client_ip_reg.read(cip, (bit<32>)meta.reg_index);
        client_port_reg.read(cport, (bit<32>)meta.reg_index);
        server_ip_reg.read(sip, (bit<32>)meta.reg_index);
        server_port_reg.read(sport, (bit<32>)meta.reg_index);
        client_isn_reg.read(cisn, (bit<32>)meta.reg_index);

        lookup_arp_mac(sip);
        if (meta.arp_mac == 0) { drop(); return; }

        hdr.ethernet.srcAddr = SWITCH_MAC;
        hdr.ethernet.dstAddr = meta.arp_mac;
        hdr.ethernet.etherType = TYPE_IPV4;

        hdr.ipv4.version = 4;
        hdr.ipv4.ihl = 5;
        hdr.ipv4.totalLen = 40;
        hdr.ipv4.ttl = 64;
        hdr.ipv4.protocol = PROTO_TCP;
        hdr.ipv4.srcAddr = cip;
        hdr.ipv4.dstAddr = sip;
        hdr.ipv4.hdrChecksum = 0;

        hdr.tcp.srcPort = cport;
        hdr.tcp.dstPort = sport;
        hdr.tcp.seqNo = cisn;
        hdr.tcp.ackNo = 0;
        hdr.tcp.dataOffset = 5;
        hdr.tcp.ctrl = TCP_SYN;
        hdr.tcp.window = 65535;
        hdr.tcp.checksum = 0;

        meta.tcpSegLen = 20;
        standard_metadata.egress_spec = 2;
        conn_state_reg.write((bit<32>)meta.reg_index, 2);
    }

    // --- Step 4: Server SYN+ACK ---
    action handle_server_synack() {
        calc_conn_index();

        bit<8> state;
        conn_state_reg.read(state, (bit<32>)meta.reg_index);
        if (state != 2) { drop(); return; }

        bit<32> client_isn; bit<32> proxy_isn;
        client_isn_reg.read(client_isn, (bit<32>)meta.reg_index);
        proxy_isn_reg.read(proxy_isn, (bit<32>)meta.reg_index);
        meta.ack_offset = proxy_isn - client_isn;
        ack_offset_reg.write((bit<32>)meta.reg_index, meta.ack_offset);

        meta.do_action = 2;
        recirculate(meta);
    }

    // --- Step 5: Send ACK to Server ---
    action send_server_ack() {
        calc_conn_index();

        bit<32> cip; bit<32> sip; bit<32> cisn; bit<32> server_seq;
        bit<16> cport; bit<16> sport;

        client_ip_reg.read(cip, (bit<32>)meta.reg_index);
        client_port_reg.read(cport, (bit<32>)meta.reg_index);
        server_ip_reg.read(sip, (bit<32>)meta.reg_index);
        server_port_reg.read(sport, (bit<32>)meta.reg_index);
        client_isn_reg.read(cisn, (bit<32>)meta.reg_index);
        server_seq = hdr.tcp.seqNo;

        lookup_arp_mac(sip);
        if (meta.arp_mac == 0) { drop(); return; }

        hdr.ethernet.srcAddr = SWITCH_MAC;
        hdr.ethernet.dstAddr = meta.arp_mac;
        hdr.ethernet.etherType = TYPE_IPV4;

        hdr.ipv4.version = 4;
        hdr.ipv4.ihl = 5;
        hdr.ipv4.totalLen = 40;
        hdr.ipv4.ttl = 64;
        hdr.ipv4.protocol = PROTO_TCP;
        hdr.ipv4.srcAddr = cip;
        hdr.ipv4.dstAddr = sip;
        hdr.ipv4.hdrChecksum = 0;

        hdr.tcp.srcPort = cport;
        hdr.tcp.dstPort = sport;
        hdr.tcp.seqNo = cisn + 1;
        hdr.tcp.ackNo = server_seq + 1;
        hdr.tcp.dataOffset = 5;
        hdr.tcp.ctrl = TCP_ACK;
        hdr.tcp.window = 65535;
        hdr.tcp.checksum = 0;

        meta.tcpSegLen = 20;
        standard_metadata.egress_spec = 2;
        conn_state_reg.write((bit<32>)meta.reg_index, 3);
    }

    // --- Forward established traffic ---
    action forward_client_to_server() {
        calc_conn_index();

        bit<8> state;
        conn_state_reg.read(state, (bit<32>)meta.reg_index);
        if (state != 3) { drop(); return; }

        bit<32> server_ip;
        server_ip_reg.read(server_ip, (bit<32>)meta.reg_index);
        lookup_arp_mac(server_ip);
        if (meta.arp_mac == 0) { drop(); return; }

        hdr.ethernet.srcAddr = SWITCH_MAC;
        hdr.ethernet.dstAddr = meta.arp_mac;

        bit<32> offset;
        seq_offset_reg.read(offset, (bit<32>)meta.reg_index);
        hdr.tcp.seqNo = hdr.tcp.seqNo + offset;

        standard_metadata.egress_spec = 2;
    }

    action forward_server_to_client() {
        calc_conn_index();

        bit<8> state;
        conn_state_reg.read(state, (bit<32>)meta.reg_index);
        if (state != 3) { drop(); return; }

        bit<32> client_ip;
        client_ip_reg.read(client_ip, (bit<32>)meta.reg_index);
        lookup_arp_mac(client_ip);
        if (meta.arp_mac == 0) { drop(); return; }

        hdr.ethernet.srcAddr = SWITCH_MAC;
        hdr.ethernet.dstAddr = meta.arp_mac;

        bit<32> offset;
        ack_offset_reg.read(offset, (bit<32>)meta.reg_index);
        hdr.tcp.ackNo = hdr.tcp.ackNo + offset;

        standard_metadata.egress_spec = 1;
    }

    // ===== Main Apply Logic =====
    apply {
        // Learn ARP from IP packets
        if (hdr.ipv4.isValid()) {
            learn_arp();
        }

        // Handle ARP
        if (hdr.arp.isValid()) {
            if (hdr.arp.opcode == ARP_REQUEST) {
                if (hdr.arp.target_proto_addr == SWITCH_IP) {
                    send_arp_reply(SWITCH_MAC, SWITCH_IP);
                    return;
                }
                calc_arp_index(hdr.arp.target_proto_addr);
                bit<48> known_mac;
                arp_table.read(known_mac, (bit<32>)meta.reg_index);
                if (known_mac != 0) {
                    send_arp_reply(known_mac, hdr.arp.target_proto_addr);
                    return;
                }
            }
            drop();
            return;
        }

        // Set direction
        if (standard_metadata.ingress_port == 1) {
            meta.direction = 0;
        } else if (standard_metadata.ingress_port == 2) {
            meta.direction = 1;
        } else {
            drop();
            return;
        }

        // Handle recirculated control packets
        if (meta.do_action == 1) {
            send_server_syn();
            return;
        }
        if (meta.do_action == 2) {
            send_server_ack();
            return;
        }

        // Handle TCP
        if (hdr.ipv4.isValid() && hdr.tcp.isValid()) {
            if (meta.direction == 0) {
                if (hdr.tcp.ctrl == TCP_SYN) {
                    handle_client_syn();
                } else if (hdr.tcp.ctrl == TCP_ACK) {
                    handle_client_ack();
                } else {
                    forward_client_to_server();
                }
            } else if (meta.direction == 1) {
                if (hdr.tcp.ctrl == TCP_SYN_ACK) {
                    handle_server_synack();
                } else {
                    forward_server_to_client();
                }
            }
        } else {
            drop();
        }
    }
}

// ===== Other Controls =====
control MyVerifyChecksum(inout headers hdr, inout metadata meta) { apply { } }
control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t sm) { apply { } }

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(hdr.ipv4.isValid(),
            { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
              hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags,
              hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol,
              hdr.ipv4.srcAddr, hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);

        update_checksum_with_payload(hdr.tcp.isValid(),
            { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 8w0, 8w6, meta.tcpSegLen },
            hdr.tcp.checksum, HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        if (hdr.arp.isValid()) packet.emit(hdr.arp);
        if (hdr.ipv4.isValid()) {
            packet.emit(hdr.ipv4);
            if (hdr.tcp.isValid()) packet.emit(hdr.tcp);
        }
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