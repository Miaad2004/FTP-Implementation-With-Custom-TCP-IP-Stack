# http_server.py
from src.core.tcp.tcp import TCPConnection
from src.common.utils import get_iface_ip, get_iface_mac, get_gateway_info
import signal

def main():
    # Get network interface details
    interface = "eth0"  # Change to your interface
    source_ip = get_iface_ip(interface)
    source_mac = get_iface_mac(interface)
    gateway_ip, gateway_mac = get_gateway_info(interface)
    print(f"Interface: {interface}")
    print(f"Source IP: {source_ip}")
    print(f"Source MAC: {source_mac}")
    print(f"Gateway IP: {gateway_ip}")
    print(f"Gateway MAC: {gateway_mac}")

    server= TCPConnection(iface=interface, iface_ip=source_ip, iface_mac=source_mac, gateway_mac=gateway_mac, listen_ip=source_ip, listen_port=8080, is_server=True)


    # Handle graceful shutdown
    def handle_signal(signum, frame):
        print("\nShutting down server...")
        server.on_terminate_signal()
        exit(0)

    signal.signal(signal.SIGINT, handle_signal)

    try:
        print(f"Starting HTTP server on {source_ip}:8080")
        server.listen(backlog=5)

        while True:
            # Accept client connection
            client, addr = server.accept()
            
            # Receive HTTP request
            data = client.receive()
            print(f"Received request:\n{data}")

            # Send HTTP response
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 13\r\n"
                "\r\n"
                "Hello, World!"
            )
            client.send(response.encode())
            client.close()

    except Exception as e:
        print(f"Error: {e}")
        raise
        server.on_terminate_signal()

if __name__ == "__main__":
    main()