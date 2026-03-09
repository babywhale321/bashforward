#!/bin/bash
#
# https://github.com/babywhale321/bashforward
# https://bashforward.com
#
# Author: Kyle Schroeder "BabyWhale"

# Configuration
DB_FILE="bashforward.db"
NGINX_CONF_DIR="/etc/nginx/conf.d"
GENERATED_CONF="${NGINX_CONF_DIR}/reverse-proxy-generated.conf"
NGINX_SERVICE="nginx"
WEBROOT="/var/www/html"  # Common webroot for Certbot challenges

# Ensure webroot exists
ensure_webroot() {
    if [[ ! -d "$WEBROOT" ]]; then
        mkdir -p "$WEBROOT"
    fi
    # Set basic permissions
    chmod 755 "$WEBROOT"
}

# Regenerate Nginx configuration from database
regenerate_config() {
    echo "Generating Nginx configuration from database..."
    
    # Backup existing generated config
    if [[ -f "$GENERATED_CONF" ]]; then
        cp "$GENERATED_CONF" "${GENERATED_CONF}.bak"
        echo "Backup created at ${GENERATED_CONF}.bak"
    fi

    # Build config in a temporary file
    TMP_CONF=$(mktemp)

    sqlite3 "$DB_FILE" "SELECT id, domain, backend_host, backend_port, ssl FROM nginx_entries;" | while IFS='|' read -r id domain backend_host backend_port ssl; do
        # HTTP server block (always present, with acme-challenge location for SSL domains)
        cat >> "$TMP_CONF" <<EOF
# Entry ID: $id - Domain: $domain
server {
    listen 80;
    server_name $domain;

    # Certbot webroot validation
    location /.well-known/acme-challenge/ {
        root $WEBROOT;
    }

    location / {
        proxy_pass http://$backend_host:$backend_port;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}

EOF

        # If SSL is enabled, generate HTTPS server block
        if [[ "$ssl" -eq 1 ]]; then
            # Check if certificate files exist (Certbot standard paths)
            CERT_FILE="/etc/letsencrypt/live/$domain/fullchain.pem"
            KEY_FILE="/etc/letsencrypt/live/$domain/privkey.pem"
            if [[ ! -f "$CERT_FILE" || ! -f "$KEY_FILE" ]]; then
                echo "SSL enabled for $domain but certificates not found at $CERT_FILE. Skipping HTTPS block."
            else
                cat >> "$TMP_CONF" <<EOF
server {
    listen 443 ssl;
    server_name $domain;

    ssl_certificate $CERT_FILE;
    ssl_certificate_key $KEY_FILE;

    # Certbot webroot validation (optional, but keep for renewals)
    location /.well-known/acme-challenge/ {
        root $WEBROOT;
    }

    location / {
        proxy_pass http://$backend_host:$backend_port;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}

EOF
            fi
        fi
    done

    # Replace the generated config with the temporary one
    mv "$TMP_CONF" "$GENERATED_CONF"
    echo "Configuration generated at $GENERATED_CONF"
}

# Test and reload Nginx
reload_nginx() {
    echo "Testing Nginx configuration..."
    if nginx -t; then
        echo "Configuration test passed. Reloading Nginx..."
        systemctl reload "$NGINX_SERVICE" || systemctl restart "$NGINX_SERVICE"
        echo "Nginx reloaded successfully."
    else
        echo "Nginx configuration test failed. Restoring backup if available."
        if [[ -f "${GENERATED_CONF}.bak" ]]; then
            cp "${GENERATED_CONF}.bak" "$GENERATED_CONF"
            echo "Backup restored."
            nginx -t && systemctl reload "$NGINX_SERVICE"
        fi
        exit 1
    fi
}

# Run Certbot for a domain (webroot mode)
run_certbot() {
    local domain=$1
    echo "Running Certbot for $domain using webroot $WEBROOT..."
    if certbot certonly --webroot -w "$WEBROOT" -d "$domain" --non-interactive --agree-tos --email webmaster@"$domain" --keep; then
        echo "Certbot succeeded for $domain."
    else
        echo "Certbot failed for $domain. SSL may not work."
    fi
}

# Add a new entry
add_entry() {
    echo ""
    read -ep "Domain (e.g., example.com): " domain
    # Check if domain already exists
    if sqlite3 "$DB_FILE" "SELECT domain FROM nginx_entries WHERE domain='$domain';" | grep -q "$domain"; then
        echo "Domain $domain already exists in database."
        return
    fi

    read -ep "Backend host (IP or hostname): " backend_host
    read -ep "Backend port: " backend_port
    read -ep "Enable SSL (via Certbot)? (y/n): " ssl_choice
    ssl=0
    if [[ "$ssl_choice" =~ ^[Yy]$ ]]; then
        ssl=1
    fi

    # Insert into database
    sqlite3 "$DB_FILE" "INSERT INTO nginx_entries (domain, backend_host, backend_port, ssl) VALUES ('$domain', '$backend_host', $backend_port, $ssl);"
    echo "Entry added."

    # Regenerate config (so HTTP block is available for Certbot validation)
    regenerate_config
    reload_nginx

    # If SSL enabled, run Certbot
    if [[ "$ssl" -eq 1 ]]; then
        run_certbot "$domain"
        # Regenerate config again to include HTTPS block now that certificates exist
        regenerate_config
        reload_nginx
    fi
}

# Delete an entry
delete_entry() {
    list_entries
    echo ""
    read -ep "Enter the ID of the entry to delete: " id
    if [[ -z "$id" ]]; then
        echo "No ID entered."
        return
    fi
    # Check if id exists
    if ! sqlite3 "$DB_FILE" "SELECT id FROM nginx_entries WHERE id=$id;" | grep -q "$id"; then
        echo "Entry with ID $id not found."
        return
    fi

    sqlite3 "$DB_FILE" "DELETE FROM nginx_entries WHERE id=$id;"
    echo "Entry deleted."

    regenerate_config
    reload_nginx
}

# List all entries
list_entries() {
    echo ""
    sqlite3 "$DB_FILE" -header -column "SELECT id, domain, backend_host, backend_port, ssl FROM nginx_entries ORDER BY id;"
}

# Show menu
show_menu() {
    echo ""
    echo -e "================= NGINX Menu ================="
    echo ""
    echo "s) List entries  1) Add entry  2) Delete entry"
    echo ""
    echo "q) Exit"
    echo ""
    read -ep "Enter an option: " choice
}

# Main script
main() {

    # Ensure Nginx is running
    if ! systemctl is-active --quiet "$NGINX_SERVICE"; then
        echo "Starting Nginx..."
        systemctl start "$NGINX_SERVICE"
        systemctl enable "$NGINX_SERVICE"
    fi

    # Ensure webroot exists
    ensure_webroot

    # Generate initial config if not exists (empty file)
    if [[ ! -f "$GENERATED_CONF" ]]; then
        regenerate_config
        reload_nginx
    fi

    # Menu
    while true; do
        show_menu
        case $choice in
            s) list_entries ;;
            1) add_entry ;;
            2) delete_entry ;;
            q) exit 0 ;;
            *) echo "Invalid selection" ;;
        esac
    done
}

# Run main function
main