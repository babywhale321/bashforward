# bashforward

## Example use cases
Port forwarding a wireguard client that has a webserver to the wireguard server so then it can be reached from the internet

wireguard client ( 10.7.0.2 port 80 ) -> wireguard server ( 123.123.123.123 port 8080 )

then when going to 123.123.123.123:8080 it wil be forwarding the clients port specified ( 80 in this case )
