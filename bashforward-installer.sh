#!/bin/bash
#
# https://github.com/babywhale321/bashforward
# https://bashforward.com
#
# Author: Kyle Schroeder "BabyWhale"

# SQLite database path
DB_FILE="bashforward.db"

# Install required packages
install_packages() {
    echo "Required packages (nginx, sqlite3, wget, qrencode, wireguard, wireguard-tools, iptables, and certbot)"
    read -ep "Press enter to install these required packages for bashforward."
    if command -v apt &>/dev/null; then
        apt update
        apt install -y nginx sqlite3 certbot python3-certbot-nginx wget qrencode wireguard wireguard-tools iptables
    else
        echo "This script is only supported by debian based operating systems."
        exit 1
    fi
}

# Function to create database file and set permissions only if it does not already exist
init_database() {
if [ ! -f "$DB_FILE" ]; then
    # Create an empty SQLite database file
    sqlite3 "$DB_FILE" "SELECT 1;" >/dev/null 2>&1
    # Set correct permissions
    chmod 600 "$DB_FILE"
    echo "Database file created: $DB_FILE"
fi
}

# Function to create wireguard_entries table
init_wireguard_table() {
    sqlite3 "$DB_FILE" "CREATE TABLE IF NOT EXISTS wireguard_entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        public_key TEXT NOT NULL,
        preshared_key TEXT NOT NULL,
        ipv4_octet INTEGER NOT NULL UNIQUE,
        dns TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );"
}

# Function to create nginx_entries table
init_nginx_table() {
    sqlite3 "$DB_FILE" "CREATE TABLE IF NOT EXISTS nginx_entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE NOT NULL,
        backend_host TEXT NOT NULL,
        backend_port INTEGER NOT NULL,
        ssl BOOLEAN DEFAULT 0
    );"
}

# Function to create portforward_entries table
init_portforwarding_table() {
    sqlite3 "$DB_FILE" "CREATE TABLE IF NOT EXISTS portforward_entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_version TEXT NOT NULL,
        external_port INTEGER NOT NULL,
        dest_ip TEXT NOT NULL,
        dest_port INTEGER NOT NULL
    );"
}


# Main
install_packages
init_database
init_wireguard_table
init_nginx_table
init_portforwarding_table

echo "==========================================================="
echo "If no errors above then you can run bashforward with"
echo "bash bashforward.sh"
echo ""
