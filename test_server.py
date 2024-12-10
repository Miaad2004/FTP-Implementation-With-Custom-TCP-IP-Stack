import socket
from src.core.arp.arp import ARP

def start_http_server():
    print(ARP.resolve_ip_to_mac("172.18.112.1"))
    return
    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Define the server address and port
    server_address = ('172.18.121.202', 8080)
    
    # Bind the socket to the address and port
    server_socket.bind(server_address)
    
    # Listen for incoming connections
    server_socket.listen(1)
    print("Server is listening on port 8080...")
    
    while True:
        # Wait for a connection
        client_socket, client_address = server_socket.accept()
        try:
            print(f"Connection from {client_address}")
            
            # Receive the request
            request = client_socket.recv(4096)
            print(f"Request: {request.decode()}")
            
            # Send HTTP response
            response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello, World!"
            client_socket.sendall(response.encode())
        
        finally:
            # Close the connection
            client_socket.close()

if __name__ == "__main__":
    start_http_server()