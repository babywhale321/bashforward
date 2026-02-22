while true; do
    echo -e "\n=============== bashforward ==============="
    echo "1. Port forwarding menu  2. Wireguard menu"  
    echo ""
    echo "q. Quit"
    read -ep "Enter your choice: " menu_choice

    case $menu_choice in
        1)  
            bash bashforward-portforwarding.sh
            ;;

        2)
            bash bashforward-nyr-wireguard.sh
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