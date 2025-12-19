there is no arp protocol in p4 file
so h1 is using broadcast to get h2
now we have finished SYN -> SYN+ACK -> ACK -> SYN to Server, but server received broadcast packet, which bug happens.