struct tcp_ts_t {
    bit<8> kind;
    bit<8> length;
    bit<32> ts_val;
    bit<32> ts_ecr;
}

struct tcp_mss_t {
    bit<8> kind;
    bit<8> length;
    bit<16> size;
}

struct tcp_sack_t {
    bit<8> kind;
    bit<8> length;
}

struct tcp_noop_t {
    bit<8> noop;
}

struct tcp_ws_t {
    bit<8> kind;
    bit<8> length;
    bit<8> shift;
}

struct tcp_option_t {
    tcp_mss_t tcp_mss;
    tcp_sack_t tcp_sack;
    tcp_ts_t tcp_ts;
    tcp_noop_t tcp_noop;
    tcp_ws_t tcp_ws;
}


 update_checksum(
                    true,
                    { hdr.ipv4.srcAddr,
                      hdr.ipv4.dstAddr,
                      8w0,
                      8w6,
                      meta.tcpSegLen,

                      hdr.tcp,
                    },
                    hdr.tcp.checksum,
                    HashAlgorithm.csum16);