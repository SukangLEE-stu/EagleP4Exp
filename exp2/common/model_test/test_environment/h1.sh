#arp -s 10.0.1.2 08:00:00:00:01:02
sysctl -w net.ipv4.tcp_timestamps=0
sudo ethtool -K eth0 rx off tx off
sudo wireshark &
sleep 8
sudo python3 sender.py
sleep 600