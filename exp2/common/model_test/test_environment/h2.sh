#arp -s 10.0.1.1 08:00:00:00:01:01
sysctl -w net.ipv4.tcp_timestamps=0
sudo ethtool -K eth0 rx off tx off
sudo wireshark &
echo 'start server'
python3 server.py
