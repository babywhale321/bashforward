# bashforward

## Example use cases
Port forwarding a wireguard client that has a webserver to a wireguard server so then it can be reached from the internet. wireguard client ( 10.7.0.2 port 80 ) -> wireguard server ( 123.123.123.123 port 8080 )

Then when going to http://123.123.123.123:8080 it will be forwarding from http://10.7.0.2:80
