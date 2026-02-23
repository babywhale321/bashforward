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

# Check for sqlite3
if ! command -v sqlite3 &> /dev/null; then
    echo "sqlite3 not found. Installing..."
    if command -v apt &> /dev/null; then
        apt update && apt install -y sqlite3
    elif command -v yum &> /dev/null; then
        yum install -y sqlite3
    else
        echo "Please install sqlite3 manually and re-run the script."
        exit 1
    fi
fi

# Configuration files and database
DB_FILE="/root/bashforward.db"
SCRIPT_FILE="/root/port-forwarding.sh"
SERVICE_FILE="/etc/systemd/system/port-forwarding.service"

# Enable IP forwarding for both IPv4 and IPv6
sysctl_conf="/etc/sysctl.conf"
for param in "net.ipv4.ip_forward=1" "net.ipv6.conf.all.forwarding=1"; do
    key=${param%=*}
    current_val=$(sysctl -n $key 2>/dev/null)
    if [ "$current_val" != "1" ]; then
        echo "Enabling $key ..."
        grep -q "^$param" $sysctl_conf || echo "$param" >> $sysctl_conf
    fi
done
sysctl -p >/dev/null

# Initialize database
init_db() {
    sqlite3 $DB_FILE "CREATE TABLE IF NOT EXISTS forwards (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_version TEXT NOT NULL,
        external_port INTEGER NOT NULL,
        dest_ip TEXT NOT NULL,
        dest_port INTEGER NOT NULL
    );"
}

# Ensure custom iptables chains exist and jump rules are present
ensure_iptables_chains() {
    # IPv4
    iptables -t nat -N PORT_FORWARDING_PREROUTING 2>/dev/null
    iptables -t nat -N PORT_FORWARDING_POSTROUTING 2>/dev/null
    if ! iptables -t nat -C PREROUTING -j PORT_FORWARDING_PREROUTING 2>/dev/null; then
        iptables -t nat -I PREROUTING -j PORT_FORWARDING_PREROUTING
    fi
    if ! iptables -t nat -C POSTROUTING -j PORT_FORWARDING_POSTROUTING 2>/dev/null; then
        iptables -t nat -I POSTROUTING -j PORT_FORWARDING_POSTROUTING
    fi
    # IPv6
    ip6tables -t nat -N PORT_FORWARDING_PREROUTING 2>/dev/null
    ip6tables -t nat -N PORT_FORWARDING_POSTROUTING 2>/dev/null
    if ! ip6tables -t nat -C PREROUTING -j PORT_FORWARDING_PREROUTING 2>/dev/null; then
        ip6tables -t nat -I PREROUTING -j PORT_FORWARDING_PREROUTING
    fi
    if ! ip6tables -t nat -C POSTROUTING -j PORT_FORWARDING_POSTROUTING 2>/dev/null; then
        ip6tables -t nat -I POSTROUTING -j PORT_FORWARDING_POSTROUTING
    fi
}

# Regenerate the persistent script from database
regenerate_script() {
    echo "#!/bin/bash" > $SCRIPT_FILE
    echo "# Port forwarding rules generated from DB" >> $SCRIPT_FILE
    echo "" >> $SCRIPT_FILE

    # Ensure custom chains and jump rules
    cat >> $SCRIPT_FILE <<'EOF'
# Ensure custom chains and jump rules
iptables -t nat -N PORT_FORWARDING_PREROUTING 2>/dev/null
iptables -t nat -N PORT_FORWARDING_POSTROUTING 2>/dev/null
iptables -t nat -C PREROUTING -j PORT_FORWARDING_PREROUTING 2>/dev/null || iptables -t nat -I PREROUTING -j PORT_FORWARDING_PREROUTING
iptables -t nat -C POSTROUTING -j PORT_FORWARDING_POSTROUTING 2>/dev/null || iptables -t nat -I POSTROUTING -j PORT_FORWARDING_POSTROUTING
ip6tables -t nat -N PORT_FORWARDING_PREROUTING 2>/dev/null
ip6tables -t nat -N PORT_FORWARDING_POSTROUTING 2>/dev/null
ip6tables -t nat -C PREROUTING -j PORT_FORWARDING_PREROUTING 2>/dev/null || ip6tables -t nat -I PREROUTING -j PORT_FORWARDING_PREROUTING
ip6tables -t nat -C POSTROUTING -j PORT_FORWARDING_POSTROUTING 2>/dev/null || ip6tables -t nat -I POSTROUTING -j PORT_FORWARDING_POSTROUTING

# Flush existing rules in custom chains
iptables -t nat -F PORT_FORWARDING_PREROUTING
iptables -t nat -F PORT_FORWARDING_POSTROUTING
ip6tables -t nat -F PORT_FORWARDING_PREROUTING
ip6tables -t nat -F PORT_FORWARDING_POSTROUTING
EOF
    echo "" >> $SCRIPT_FILE

    # Get all forwards
    local count=$(sqlite3 $DB_FILE "SELECT COUNT(*) FROM forwards;")
    if [ "$count" -gt 0 ]; then
        # Add MASQUERADE rule in POSTROUTING chain (once)
        echo "# Add MASQUERADE for IPv4" >> $SCRIPT_FILE
        echo "iptables -t nat -A PORT_FORWARDING_POSTROUTING -j MASQUERADE" >> $SCRIPT_FILE
        echo "# Add MASQUERADE for IPv6" >> $SCRIPT_FILE
        echo "ip6tables -t nat -A PORT_FORWARDING_POSTROUTING -j MASQUERADE" >> $SCRIPT_FILE
        echo "" >> $SCRIPT_FILE

        # Process each forward
        sqlite3 $DB_FILE "SELECT ip_version, external_port, dest_ip, dest_port FROM forwards;" | while IFS="|" read ver eport dip dport; do
            if [ "$ver" == "v4" ]; then
                echo "iptables -t nat -A PORT_FORWARDING_PREROUTING -p tcp --dport $eport -j DNAT --to-destination $dip:$dport" >> $SCRIPT_FILE
                echo "iptables -t nat -A PORT_FORWARDING_PREROUTING -p udp --dport $eport -j DNAT --to-destination $dip:$dport" >> $SCRIPT_FILE
            else
                echo "ip6tables -t nat -A PORT_FORWARDING_PREROUTING -p tcp --dport $eport -j DNAT --to-destination [$dip]:$dport" >> $SCRIPT_FILE
                echo "ip6tables -t nat -A PORT_FORWARDING_PREROUTING -p udp --dport $eport -j DNAT --to-destination [$dip]:$dport" >> $SCRIPT_FILE
            fi
        done
    else
        echo "# No forwards configured." >> $SCRIPT_FILE
    fi
    chmod +x $SCRIPT_FILE
}

# Apply the current rules from the script
apply_rules() {
    bash $SCRIPT_FILE
}

# Create systemd service if it doesn't exist
ensure_systemd_service() {
    if [ ! -f "$SERVICE_FILE" ]; then
        cat > $SERVICE_FILE <<EOF
[Unit]
Description=Port Forwarding Rules
After=network.target

[Service]
Type=oneshot
ExecStart=$SCRIPT_FILE
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable port-forwarding.service
    fi
}

# Add a new forwarding rule
add_forward() {
    echo "--- Add New Forward ---"
    
    # IP version
    while true; do
        read -ep "Enter the IP version (v4/v6): " ip_version
        ip_version=$(echo "$ip_version" | tr '[:upper:]' '[:lower:]')
        [[ "$ip_version" == "v4" || "$ip_version" == "v6" ]] && break
        echo "Invalid IP version. Please enter v4 or v6."
    done

    # External port
    while true; do
        read -ep "Enter the external port (1-65535): " external_port
        [[ $external_port =~ ^[0-9]+$ ]] && \
        [ $external_port -ge 1 -a $external_port -le 65535 ] && break
        echo "Invalid port. Must be 1-65535."
    done

    # Destination IP
    while true; do
        read -ep "Enter the destination IP ($ip_version): " dest_ip
        if [ "$ip_version" == "v4" ]; then
            validate_ipv4 "$dest_ip" && break
        else
            validate_ipv6 "$dest_ip" && break
        fi
        echo "Invalid $ip_version address."
    done

    # Destination port
    while true; do
        read -ep "Enter the destination port (1-65535): " dest_port
        [[ $dest_port =~ ^[0-9]+$ ]] && \
        [ $dest_port -ge 1 -a $dest_port -le 65535 ] && break
        echo "Invalid port. Must be 1-65535."
    done

    # Insert into database
    sqlite3 $DB_FILE "INSERT INTO forwards (ip_version, external_port, dest_ip, dest_port) VALUES ('$ip_version', $external_port, '$dest_ip', $dest_port);"
    
    # Regenerate script and apply
    regenerate_script
    apply_rules
    
    echo "Forward added successfully."
    
}

# List all forwards
list_forwards() {
    echo "--- Current Forwards ---"
    sqlite3 $DB_FILE "SELECT id, ip_version, external_port, dest_ip, dest_port FROM forwards;" | while IFS="|" read id ver eport dip dport; do
        printf "ID: %d | %s | Ext Port: %d | Destination: %s:%d\n" "$id" "$ver" "$eport" "$dip" "$dport"
    done
    if [ $(sqlite3 $DB_FILE "SELECT COUNT(*) FROM forwards;") -eq 0 ]; then
        echo "No forwards configured."
    fi
    
}

# Delete a forward by ID
delete_forward() {
    echo "--- Delete Forward ---"
    list_forwards
    if [ $(sqlite3 $DB_FILE "SELECT COUNT(*) FROM forwards;") -eq 0 ]; then
        return
    fi
    read -ep "Enter the ID of the forward to delete: " id
    if ! [[ $id =~ ^[0-9]+$ ]]; then
        echo "Invalid ID."
        
        return
    fi
    # Check if exists
    if [ $(sqlite3 $DB_FILE "SELECT COUNT(*) FROM forwards WHERE id=$id;") -eq 0 ]; then
        echo "ID not found."
        
        return
    fi
    sqlite3 $DB_FILE "DELETE FROM forwards WHERE id=$id;"
    regenerate_script
    apply_rules
    echo "Forward deleted."
    
}

# Reset all forwards
reset_all() {
    echo "--- Reset All Forwards ---"
    read -ep "Are you sure? This will delete all forwards. (y/n): " confirm
    confirm=$(echo "$confirm" | tr '[:upper:]' '[:lower:]')
    if [[ "$confirm" == "y" || "$confirm" == "yes" ]]; then
        sqlite3 $DB_FILE "DELETE FROM forwards;"
        regenerate_script
        apply_rules
        echo "All forwards cleared."
    else
        echo "Cancelled."
    fi
    
}

# --- Main ---
init_db
ensure_iptables_chains
ensure_systemd_service

# Manage Port forwarding
while true; do
    echo -e "\n==================================== bashforward ===================================="
    echo "s. Show port forwarding rules        1. Add a forwarding rule  2. Delete a forwarding rule"  
    echo "3. Reset all forwarding rules        q. Quit"
    echo ""
    read -ep "Enter your choice: " menu_choice

    case $menu_choice in
        s)  
            list_forwards
            ;;

        1)
            add_forward
            ;;

        2)
            delete_forward
            ;;

        3)
            reset_all
            ;;

        q)
            # Exit
            break
            ;;

        *)
            echo "Invalid choice. Please enter a valid option."
            ;;
    esac
done