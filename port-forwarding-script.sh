#!/bin/bash

# Check if user is root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root or with sudo"
    exit 1
fi

# Function to validate IPv4 address
validate_ipv4() {
    local ip=$1
    local stat=1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && \
           ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}

# Function to validate IPv6 address
validate_ipv6() {
    local ip=$1
    local stat=1
    local pattern='^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$'
    [[ $ip =~ $pattern ]] && stat=0
    return $stat
}

# Configuration file
port_forwarding_file="/root/port-forwarding.sh"
read -ep "Would you like to wipe any previous configurations? (y/n): " wipe_config
wipe_config=$(echo "$wipe_config" | tr '[:upper:]' '[:lower:]')
if [[ "$wipe_config" == "y" || "$wipe_config" == "ye" || "$wipe_config" == "yes" ]]; then
    rm "$port_forwarding_file"
fi

# Get IP version
while true; do
    read -ep "Enter the IP version (v4/v6): " ip_version
    ip_version=$(echo "$ip_version" | tr '[:upper:]' '[:lower:]')
    [[ "$ip_version" == "v4" || "$ip_version" == "v6" ]] && break
    echo "Invalid IP version. Please enter v4 or v6."
done

# Get external port
while true; do
    read -ep "Enter the external port that will be exposed to the internet (This device): " external_port
    [[ $external_port =~ ^[0-9]+$ ]] && \
    [ $external_port -ge 1 -a $external_port -le 65535 ] && break
    echo "Invalid port. Must be 1-65535."
done

# Get destination IP
while true; do
    read -ep "Enter the destination IP that will be forwarded externally (To this device)($ip_version): " dest_ip
    if [ "$ip_version" == "v4" ]; then
        validate_ipv4 "$dest_ip" && break
    else
        validate_ipv6 "$dest_ip" && break
    fi
    echo "Invalid $ip_version address."
done

# Get destination port
while true; do
    read -ep "Enter the destination port that will be forwarded to the external port (To this device): " dest_port
    [[ $dest_port =~ ^[0-9]+$ ]] && \
    [ $dest_port -ge 1 -a $dest_port -le 65535 ] && break
    echo "Invalid port. Must be 1-65535."
done

# Enable IP forwarding
sysctl_conf="/etc/sysctl.conf"
if [ "$ip_version" == "v4" ]; then
    sysctl_param="net.ipv4.ip_forward=1"
    current_val=$(sysctl -n net.ipv4.ip_forward)
else
    sysctl_param="net.ipv6.conf.all.forwarding=1"
    current_val=$(sysctl -n net.ipv6.conf.all.forwarding)
fi

if [ $current_val -ne 1 ]; then
    echo "Enabling IP forwarding..."
    grep -q "^$sysctl_param" $sysctl_conf || echo "$sysctl_param" >> $sysctl_conf
    sysctl -p >/dev/null
fi

# Configure NAT rules
if [ "$ip_version" == "v4" ]; then
    iptables -t nat -A PREROUTING -p tcp --dport $external_port -j DNAT --to-destination ${dest_ip}:${dest_port}
    iptables -t nat -A POSTROUTING -j MASQUERADE
    iptables -t nat -A PREROUTING -p udp --dport $external_port -j DNAT --to-destination ${dest_ip}:${dest_port}
    iptables -t nat -A POSTROUTING -j MASQUERADE
    echo "iptables -t nat -A PREROUTING -p tcp --dport $external_port -j DNAT --to-destination ${dest_ip}:${dest_port}" >> "$port_forwarding_file"
    echo "iptables -t nat -A POSTROUTING -j MASQUERADE" >> "$port_forwarding_file"
    echo "iptables -t nat -A PREROUTING -p udp --dport $external_port -j DNAT --to-destination ${dest_ip}:${dest_port}" >> "$port_forwarding_file"
    echo "iptables -t nat -A POSTROUTING -j MASQUERADE" >> "$port_forwarding_file"
else
    ip6tables -t nat -A PREROUTING -p tcp --dport $external_port -j DNAT --to-destination [${dest_ip}]:${dest_port}
    ip6tables -t nat -A POSTROUTING -j MASQUERADE
    ip6tables -t nat -A PREROUTING -p udp --dport $external_port -j DNAT --to-destination [${dest_ip}]:${dest_port}
    ip6tables -t nat -A POSTROUTING -j MASQUERADE
    echo "ip6tables -t nat -A PREROUTING -p tcp --dport $external_port -j DNAT --to-destination [${dest_ip}]:${dest_port}" >> "$port_forwarding_file"
    echo "ip6tables -t nat -A POSTROUTING -j MASQUERADE" >> "$port_forwarding_file"
    echo "ip6tables -t nat -A PREROUTING -p udp --dport $external_port -j DNAT --to-destination [${dest_ip}]:${dest_port}" >> "$port_forwarding_file"
    echo "ip6tables -t nat -A POSTROUTING -j MASQUERADE" >> "$port_forwarding_file"
fi

# Systemd service creation
port_forwarding_service="/etc/systemd/system/port-forwarding.service"
if [ ! -f "$port_forwarding_service" ]; then
    echo "[Unit]" > "$port_forwarding_service"
    echo "Description=save port-forwarding rules service" >> "$port_forwarding_service"
    echo "After=network.target" >> "$port_forwarding_service"
    echo "[Service]" >> "$port_forwarding_service"
    echo "Type=oneshot" >> "$port_forwarding_service"
    echo "ExecStart=bash $port_forwarding_file" >> "$port_forwarding_service"
    echo "[Install]" >> "$port_forwarding_service"
    echo "WantedBy=multi-user.target" >> "$port_forwarding_service"
    systemctl enable port-forwarding
fi

echo "Port forwarding configured:"
echo "External port: $external_port/tcp"
echo "External port: $external_port/udp"
echo "Destination: $dest_ip:$dest_port"
echo "IP version: $ip_version"