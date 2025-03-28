sudo modprobe tun
lsmod | grep tun                    -> should see tun
sudo ip tuntap add dev main_tun mode tun 
sudo ip addr add 10.0.0.1/24 dev main_tun
sudo ip link set main_tun up
ip addr show main_tun 
sudo ip route add 10.0.0.0/24 dev main_tun
ip route show
nano /etc/sysctl.conf               -> net.ipv4.ip_forward=1
sudo sysctl -p
sudo iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE
sudo apt install iptables-persistent
sudo netfilter-persistent save
ping 10.0.0.1                       -> should ping


run script with:
sudo chmod +x /etc/network/if-up.d/create_tun