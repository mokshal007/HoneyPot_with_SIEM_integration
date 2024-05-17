import socket
import logging
import threading
import requests
import geoip2.database

# Setup logging
def setup_logging():
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        filename='honeypot.log',
                        filemode='a')

# Send alert to Discord
def send_discord_alert(message):
    webhook_url = 'https://discord.com/api/webhooks/1114116826872426537/FCU_xPsLZYTV60DEvsDmQTDzE5_Z98hL4AoYGtw7eQj5wz70uzsydIc2QJwb8wGu4SNx'
    data = {
        "content": message
    }
    response = requests.post(webhook_url, json=data)
    if response.status_code == 204:
        logging.info("Successfully sent alert to Discord")
    else:
        logging.error(f"Failed to send alert to Discord: {response.status_code}")

# Perform geolocation tracking
def perform_geolocation(ip_address):
    try:
        reader = geoip2.database.Reader('GeoLite2-City.mmdb')
        response = reader.city(ip_address)
        country = response.country.name
        city = response.city.name
        return f"{city}, {country}"
    except Exception as e:
        logging.error(f"Error performing geolocation tracking: {e}")
        return "Unknown"

# Create a socket and listen on a specified port
def create_socket(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(5)
    return s

# Handle SSH connections
def handle_ssh_connection(client_socket, client_address):
    try:
        logging.info(f"SSH connection from {client_address}")
        send_discord_alert(f"SSH connection from {client_address}")
        client_socket.sendall(b"Welcome to SSH server!\nLogin: ")
        username = client_socket.recv(1024).strip()
        logging.info(f"SSH login attempt with username: {username.decode()}")
        send_discord_alert(f"SSH login attempt with username: {username.decode()}")
        client_socket.sendall(b"Password: ")
        password = client_socket.recv(1024).strip()
        logging.info(f"SSH attempted password: {password.decode()}")
        send_discord_alert(f"SSH attempted password: {password.decode()}")

        # Perform geolocation tracking
        location = perform_geolocation(client_address[0])
        logging.info(f"Geolocation: {location}")
        send_discord_alert(f"Geolocation: {location}")

        client_socket.sendall(b"Unauthorized access! This incident will be reported.\n")
        client_socket.close()
    except Exception as e:
        logging.error(f"Error handling SSH connection: {e}")

# Handle HTTP connections
def handle_http_connection(client_socket, client_address):
    try:
        logging.info(f"HTTP connection from {client_address}")
        send_discord_alert(f"HTTP connection from {client_address}")
        request = client_socket.recv(1024).decode()
        logging.info(f"HTTP request: {request}")
        send_discord_alert(f"HTTP request: {request}")

        # Perform geolocation tracking
        location = perform_geolocation(client_address[0])
        logging.info(f"Geolocation: {location}")
        send_discord_alert(f"Geolocation: {location}")

        response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>Welcome to the honeypot HTTP server!</h1>"
        client_socket.sendall(response.encode())
        client_socket.close()
    except Exception as e:
        logging.error(f"Error handling HTTP connection: {e}")

# Handle FTP connections
def handle_ftp_connection(client_socket, client_address):
    try:
        logging.info(f"FTP connection from {client_address}")
        send_discord_alert(f"FTP connection from {client_address}")
        client_socket.sendall(b"220 Welcome to the FTP server\r\n")
        command = client_socket.recv(1024).strip()
        logging.info(f"FTP command: {command.decode()}")
        send_discord_alert(f"FTP command: {command.decode()}")

        # Perform geolocation tracking
        location = perform_geolocation(client_address[0])
        logging.info(f"Geolocation: {location}")
        send_discord_alert(f"Geolocation: {location}")

        client_socket.sendall(b"530 Not logged in\r\n")
        client_socket.close()
    except Exception as e:
        logging.error(f"Error handling FTP connection: {e}")

# Start the server
def start_server(host, port, handler):
    server_socket = create_socket(host, port)
    logging.info(f"Listening for incoming connections on port {port}")
    try:
        while True:
            client_socket, addr = server_socket.accept()
            threading.Thread(target=handler, args=(client_socket, addr)).start()
    except KeyboardInterrupt:
        logging.info("Shutting down the server.")
    finally:
        server_socket.close()

# Main function
def main():
    setup_logging()
    host = '0.0.0.0'

    ssh_port = 2222
    http_port = 8080
    ftp_port = 2121

    threading.Thread(target=start_server, args=(host, ssh_port, handle_ssh_connection)).start()
    threading.Thread(target=start_server, args=(host, http_port, handle_http_connection)).start()
    threading.Thread(target=start_server, args=(host, ftp_port, handle_ftp_connection)).start()

if __name__ == "__main__":
    main()
