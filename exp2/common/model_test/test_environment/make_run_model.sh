#!/bin/bash
echo 'lsk11111' | sudo -S make clean
rm *.p4
sudo rm *.log
cp ../../../p4/eagle_syn_proxy.p4 eagle_syn_proxy.p4
# qwen version is fake
#cp ../../../p4/synproxy_qwen.p4 eagle_syn_proxy.p4
sudo -S make run
