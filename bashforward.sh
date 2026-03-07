while true; do
    echo ""
    echo -e "===================== bashforward ====================="
    echo "1. Port Forwarding Menu  2. Wireguard Menu  3. NGINX menu"
    echo ""
    echo "q. Quit"
    echo ""
    read -ep "Enter an option: " choice

    case $choice in
        1)  
            bash bashforward-portforwarding.sh
            ;;

        2)
            bash bashforward-nyr-wireguard.sh
            ;;

        3)
            bash bashforward-nginx.sh
            ;;
        q)
            # Exit
            break
            ;;

        *)
            echo "Invalid selection"
            ;;
    esac
done