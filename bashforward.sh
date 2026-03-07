while true; do
    echo -e "\n=============== bashforward ==============="
    echo "1. Port forwarding menu  2. Wireguard menu"
    echo "3. NGINX menu"
    echo ""
    echo "q. Quit"
    read -ep "Choose an option: " choice

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