#!/usr/bin/env python3
import argparse
import socket
import json


class KDC:

    def __init__(self, host, port):
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_sock.bind((host, port))
        self.clients = []  # List of clients, where each client is a dict with keys "username", "ip", and "port"

        print("KDC Server Initialized...")

    # Function to handle LIST command
    def list_command(self, client_addr, clients):
        online_users = list(clients.keys())
        message_to_send = f"Signed In Users: {', '.join(online_users)}"
        response = {'type': 'LIST', 'content': message_to_send}

        self.server_sock.sendto(json.dumps(response).encode(), client_addr)


    # Function to handle MESSAGE command
    # def message_command(server, message, client_address, clients):


    # Main function to handle incoming messages
    def run_server(self):
        # s_socket.listen()
        # print(f"Server listening on {host}:{port}")
        print("waiting for clients...")
        while True:
            data, client_address = self.server_sock.recvfrom(4096)
            message = json.loads(data.decode())
            print(f"received: {message} from {client_address}")
            if message:
                self.server_sock.sendto(json.dumps("i recieved shit from you").encode(), client_address)

            # # Identify the message type
            # if message['type'] == 'SIGN-IN':
            #     # Handle sign-in message
            #     signin(message, client_address, clients)
            # elif message['type'] == 'LIST':
            #     # Handle list command
            #     list_command(server, client_address, clients)
            # elif message['type'] == 'MESSAGE':
            #     # Handle message command
            #     message_command(server, message, client_address, clients)


if __name__ == "__main__":
    with open('config.json') as f:
        server_info = json.load(f)

    kdc = KDC(server_info["KDC_HOST"], server_info["KDC_PORT"])
    kdc.run_server()
