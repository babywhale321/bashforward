#!/bin/bash
#
# https://github.com/Nyr/wireguard-install
#
# Copyright (c) 2020 Nyr. Released under the MIT License.
#
# https://github.com/babywhale321/bashforward
# https://bashforward.com
#
# Edited by Kyle Schroeder "BabyWhale" for bashforward
#

# Discard stdin. Needed when running from a one-liner which includes a newline
read -N 999999 -t 0.001

# Detect environments where $PATH does not include the sbin directories
if ! grep -q sbin <<< "$PATH"; then
    echo '$PATH does not include sbin. Try using "su -" instead of "su".'
    exit 1
fi

# Store the absolute path of the directory where the script is located
script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# SQLite database path
DB_FILE="bashforward.db"

# Find the smallest free IPv4 octet (2-254) using the database
find_free_octet() {
    local octet=2
    while true; do
        if [[ $octet -ge 255 ]]; then
            echo "253 wireguard_entries are already configured. The WireGuard internal subnet is full!" >&2
            exit 1
        fi
        if ! sqlite3 "$DB_FILE" "SELECT 1 FROM wireguard_entries WHERE ipv4_octet = $octet;" | grep -q 1; then
            echo $octet
            return
        fi
        ((octet++))
    done
}

new_client_dns () {
    echo "Select a DNS server for the client:"
    echo "   1) Default system resolvers"
    echo "   2) Google"
    echo "   3) Cloudflare"
    echo "   4) OpenDNS"
    echo "   5) Quad9"
    echo "   6) Gcore"
    echo "   7) AdGuard"
    echo "   8) Specify custom resolvers"
    read -ep "DNS server [1]: " dns
    until [[ -z "$dns" || "$dns" =~ ^[1-8]$ ]]; do
        echo "$dns: invalid selection."
        read -ep "DNS server [1]: " dns
    done
    case "$dns" in
        1|"")
            # Locate the proper resolv.conf
            if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53' ; then
                resolv_conf="/etc/resolv.conf"
            else
                resolv_conf="/run/systemd/resolve/resolv.conf"
            fi
            dns=$(grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | xargs | sed -e 's/ /, /g')
        ;;
        2) dns="8.8.8.8, 8.8.4.4" ;;
        3) dns="1.1.1.1, 1.0.0.1" ;;
        4) dns="208.67.222.222, 208.67.220.220" ;;
        5) dns="9.9.9.9, 149.112.112.112" ;;
        6) dns="95.85.95.85, 2.56.220.2" ;;
        7) dns="94.140.14.14, 94.140.15.15" ;;
        8)
            until [[ -n "$custom_dns" ]]; do
                echo "Enter DNS servers (one or more IPv4 addresses, separated by commas or spaces):"
                read -ep "DNS servers: " dns_input
                dns_input=$(echo "$dns_input" | tr ',' ' ')
                for dns_ip in $dns_input; do
                    if [[ "$dns_ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
                        if [[ -z "$custom_dns" ]]; then
                            custom_dns="$dns_ip"
                        else
                            custom_dns="$custom_dns, $dns_ip"
                        fi
                    fi
                done
                if [ -z "$custom_dns" ]; then
                    echo "Invalid input."
                else
                    dns="$custom_dns"
                fi
            done
        ;;
    esac
}

new_client_setup () {
    octet=$(find_free_octet)
    key=$(wg genkey)
    psk=$(wg genpsk)

    dns_escaped="${dns//\'/\'\'}"
    sqlite3 "$DB_FILE" "INSERT INTO wireguard_entries (name, public_key, preshared_key, ipv4_octet, dns) VALUES ('$client', '$(wg pubkey <<< $key)', '$psk', $octet, '$dns_escaped');"

    cat << EOF >> /etc/wireguard/wg0.conf
# BEGIN_PEER $client
[Peer]
PublicKey = $(wg pubkey <<< $key)
PresharedKey = $psk
AllowedIPs = 10.7.0.$octet/32$(grep -q 'fddd:2c4:2c4:2c4::1' /etc/wireguard/wg0.conf && echo ", fddd:2c4:2c4:2c4::$octet/128")
# END_PEER $client
EOF

    cat << EOF > "$script_dir"/"$client".conf
[Interface]
Address = 10.7.0.$octet/24$(grep -q 'fddd:2c4:2c4:2c4::1' /etc/wireguard/wg0.conf && echo ", fddd:2c4:2c4:2c4::$octet/64")
DNS = $dns
PrivateKey = $key

[Peer]
PublicKey = $(grep PrivateKey /etc/wireguard/wg0.conf | cut -d " " -f 3 | wg pubkey)
PresharedKey = $psk
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $(grep '^# ENDPOINT' /etc/wireguard/wg0.conf | cut -d " " -f 3):$(grep ListenPort /etc/wireguard/wg0.conf | cut -d " " -f 3)
PersistentKeepalive = 25
EOF
}

if [[ ! -e /etc/wireguard/wg0.conf ]]; then

    # IPv4 selection
    if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
        ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
    else
        number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
        echo ""
        echo "Which IPv4 address should be used?"
        ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
        read -ep "IPv4 address [1]: " ip_number
        until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
            echo "$ip_number: invalid selection."
            read -ep "IPv4 address [1]: " ip_number
        done
        [[ -z "$ip_number" ]] && ip_number="1"
        ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
    fi

    # NAT detection
    if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
        echo ""
        echo "This server is behind NAT. What is the public IPv4 address or hostname?"
        get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
        read -ep "Public IPv4 address / hostname [$get_public_ip]: " public_ip
        until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
            echo "Invalid input."
            read -ep "Public IPv4 address / hostname: " public_ip
        done
        [[ -z "$public_ip" ]] && public_ip="$get_public_ip"
    fi

    # IPv6 selection
    if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
        ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
    elif [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
        number_of_ip6=$(ip -6 addr | grep -c 'inet6 [23]')
        echo ""
        echo "Which IPv6 address should be used?"
        ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
        read -ep "IPv6 address [1]: " ip6_number
        until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$number_of_ip6" ]]; do
            echo "$ip6_number: invalid selection."
            read -ep "IPv6 address [1]: " ip6_number
        done
        [[ -z "$ip6_number" ]] && ip6_number="1"
        ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
    fi

    echo ""
    read -ep "Port [51820]: " port
    until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
        echo "$port: invalid port."
        read -ep "Port [51820]: " port
    done
    [[ -z "$port" ]] && port="51820"

    echo ""
    echo "Enter a name for the first client:"
    read -ep "Name [client]: " unsanitized_client
    client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
    [[ -z "$client" ]] && client="client"

    echo ""
    new_client_dns
    echo ""
    echo "WireGuard installation is ready to begin."

    # Verify required tools
    missing=()
    if ! hash wg 2>/dev/null; then missing+=("wireguard-tools (wg)"); fi
    if ! hash qrencode 2>/dev/null; then missing+=("qrencode"); fi
    if ! hash sqlite3 2>/dev/null; then missing+=("sqlite3"); fi
    if ! hash iptables 2>/dev/null; then missing+=("iptables"); fi
    if [[ -n "$ip6" ]] && ! hash ip6tables 2>/dev/null; then missing+=("ip6tables"); fi
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "The following required tools are missing:"
        printf '  %s\n' "${missing[@]}"
        echo "Please install them and re-run this script."
        exit 1
    fi

    read -n1 -r -p "Press any key to continue..."

    # Generate wg0.conf
    cat << EOF > /etc/wireguard/wg0.conf
# Do not alter the commented lines
# They are used by wireguard-install
# ENDPOINT $([[ -n "$public_ip" ]] && echo "$public_ip" || echo "$ip")

[Interface]
Address = 10.7.0.1/24$([[ -n "$ip6" ]] && echo ", fddd:2c4:2c4:2c4::1/64")
PrivateKey = $(wg genkey)
ListenPort = $port

EOF
    chmod 600 /etc/wireguard/wg0.conf

    # Enable IP forwarding
    echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wireguard-forward.conf
    echo 1 > /proc/sys/net/ipv4/ip_forward
    if [[ -n "$ip6" ]]; then
        echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-wireguard-forward.conf
        echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
    fi

    # Set up iptables rules via systemd service
    iptables_path=$(command -v iptables)
    ip6tables_path=$(command -v ip6tables)
    # Handle OVZ with nftables backend
    if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$iptables_path" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
        iptables_path=$(command -v iptables-legacy)
        ip6tables_path=$(command -v ip6tables-legacy)
    fi

    cat << EOF > /etc/systemd/system/wg-iptables.service
[Unit]
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$iptables_path -w 5 -t nat -A POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to $ip
ExecStart=$iptables_path -w 5 -I INPUT -p udp --dport $port -j ACCEPT
ExecStart=$iptables_path -w 5 -I FORWARD -s 10.7.0.0/24 -j ACCEPT
ExecStart=$iptables_path -w 5 -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -w 5 -t nat -D POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to $ip
ExecStop=$iptables_path -w 5 -D INPUT -p udp --dport $port -j ACCEPT
ExecStop=$iptables_path -w 5 -D FORWARD -s 10.7.0.0/24 -j ACCEPT
ExecStop=$iptables_path -w 5 -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
EOF

    if [[ -n "$ip6" ]]; then
        cat << EOF >> /etc/systemd/system/wg-iptables.service
ExecStart=$ip6tables_path -w 5 -t nat -A POSTROUTING -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to $ip6
ExecStart=$ip6tables_path -w 5 -I FORWARD -s fddd:2c4:2c4:2c4::/64 -j ACCEPT
ExecStart=$ip6tables_path -w 5 -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -w 5 -t nat -D POSTROUTING -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to $ip6
ExecStop=$ip6tables_path -w 5 -D FORWARD -s fddd:2c4:2c4:2c4::/64 -j ACCEPT
ExecStop=$ip6tables_path -w 5 -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
EOF
    fi

    echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/wg-iptables.service

    systemctl enable --now wg-iptables.service

    # Create first client
    new_client_setup

    # Enable and start WireGuard
    systemctl enable --now wg-quick@wg0.service

    echo ""
    qrencode -t ANSI256UTF8 < "$script_dir"/"$client.conf"
    echo -e '\xE2\x86\x91 That is a QR code containing the client configuration.'
    echo ""
    echo "Finished!"
    echo ""
    echo "The client configuration is available in:" "$script_dir"/"$client.conf"
    echo "New wireguard_entries can be added by running this script again."

else
    
	# WireGuard menu
    while true; do
        echo ""
        echo -e "================ Wireguard menu ================"
        echo "s) List current clients       1) Add a new client"
        echo "2) Remove an existing client  q) Exit"
        echo ""
        read -ep "Enter an option: " choice
        case "$choice" in
            s)
                echo ""
                sqlite3 "$DB_FILE" -header -column "SELECT id, name, ipv4_octet AS IP_octet, dns, created_at FROM wireguard_entries ORDER BY id;"
            ;;
            1)
                echo ""
                echo "Provide a name for the client:"
                read -ep "Name: " unsanitized_client
                client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
                while [[ -z "$client" ]] || sqlite3 "$DB_FILE" "SELECT 1 FROM wireguard_entries WHERE name = '$client';" | grep -q 1; do
                    echo "$client: invalid or already used name."
                    read -ep "Name: " unsanitized_client
                    client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
                done
                echo ""
                new_client_dns
                new_client_setup
                wg addconf wg0 <(sed -n "/^# BEGIN_PEER $client/,/^# END_PEER $client/p" /etc/wireguard/wg0.conf)
                echo ""
                qrencode -t ANSI256UTF8 < "$script_dir"/"$client.conf"
                echo -e '\xE2\x86\x91 That is a QR code containing your client configuration.'
                echo ""
                echo "$client added. Configuration available in:" "$script_dir"/"$client.conf"
            ;;
            2)
                mapfile -t wireguard_entries < <(sqlite3 "$DB_FILE" "SELECT name FROM wireguard_entries ORDER BY id;")
                number_of_clients=${#wireguard_entries[@]}
                if [[ "$number_of_clients" -eq 0 ]]; then
                    echo ""
                    echo "There are no existing wireguard_entries!"
                    continue
                fi
                echo ""
                echo "Select the client to remove:"
                for i in "${!wireguard_entries[@]}"; do
                    echo "$((i+1))) ${wireguard_entries[i]}"
                done
                read -ep "Client: " client_number
                until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
                    echo "$client_number: invalid selection."
                    read -ep "Client: " client_number
                done
                client="${wireguard_entries[$((client_number-1))]}"
                echo ""
                read -ep "Confirm $client removal? [y/N]: " remove
                until [[ "$remove" =~ ^[yYnN]*$ ]]; do
                    echo "$remove: invalid selection."
                    read -ep "Confirm $client removal? [y/N]: " remove
                done
                if [[ "$remove" =~ ^[yY]$ ]]; then
                    pubkey=$(sqlite3 "$DB_FILE" "SELECT public_key FROM wireguard_entries WHERE name = '$client';")
                    wg set wg0 peer "$pubkey" remove
                    sed -i "/^# BEGIN_PEER $client$/,/^# END_PEER $client$/d" /etc/wireguard/wg0.conf
                    sqlite3 "$DB_FILE" "DELETE FROM wireguard_entries WHERE name = '$client';"
                    echo ""
                    echo "$client removed!"
                else
                    echo ""
                    echo "$client removal aborted!"
                fi
            ;;
            q) exit 0 ;;
            *) echo "Invalid selection" ;;
        esac
    done
fi