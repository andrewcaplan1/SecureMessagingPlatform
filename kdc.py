#!/usr/bin/env python3
import argparse
import socket
import json


# Function to parse command line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description='KDC Server')
    # parser.add_argument('-sp', dest='port', type=int, help='Server port', required=True)
    return parser.parse_args()


# Function to handle LIST command
def list_command(server, client_addr, clients):
    online_users = list(clients.keys())
    message_to_send = f"Signed In Users: {', '.join(online_users)}"
    response = {'type': 'LIST', 'content': message_to_send}

    server.sendto(json.dumps(response).encode(), client_addr)


# Function to handle MESSAGE command
# def message_command(server, message, client_address, clients):


# Main function to handle incoming messages
def run_server():
    args = parse_arguments()
    clients = {}  # Dictionary to store client information (username, ip, port)

    print("waiting for clients...")
    while True:
        data, client_address = server.recvfrom(4096)
        message = json.loads(data.decode())
        print(f"received: {message} from {client_address}")

        # Identify the message type
        if message['type'] == 'SIGN-IN':
            # Handle sign-in message
            signin(message, client_address, clients)
        elif message['type'] == 'LIST':
            # Handle list command
            list_command(server, client_address, clients)
        elif message['type'] == 'MESSAGE':
            # Handle message command
            message_command(server, message, client_address, clients)


if __name__ == "__main__":
    run_server()
