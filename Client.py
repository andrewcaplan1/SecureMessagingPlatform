#!/usr/bin/env python3
import socket
import argparse
import json
import threading


def list_users():
    # Placeholder for the functionality to list users.
    # In a real application, this might fetch and display a list of users from a database or an API.
    print("Listing all users...")


def send_message(user_id, message):
    # Placeholder for the functionality to send a message to a user.
    # This would involve sending the message to the specified user, perhaps through an API or messaging service.
    print(f"Sending message to user {user_id}: {message}")


def parse_args():
    parser = argparse.ArgumentParser(description="Secure messaging client with command-line interface")
    # parser.add_argument('-p', dest='port', type=int, help='Client port')
    # parser.add_argument("command", choices=["list", "send"], help="Command to execute")
    # parser.add_argument("user", nargs="?", help="User to send message to (required for send command)")
    # parser.add_argument("message", nargs="?", help="Message to send (required for send command)")
    return parser.parse_args()


# Function to handle incoming messages
def receive_messages(client_socket):
    while True:
        try:
            data = client_socket.recv(4096)
            message = json.loads(data.decode())
            # if message['type'] == 'MESSAGE':
            print(message['content'])
        except socket.timeout:
            continue
    print("Receiving message...")

def sendToKDC(client_socket, addr, message):

def sendToUser()

def main():
    args = parse_args()

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.bind(('', 0))
    client_port = client_socket.getsockname()[1]
    print(f"Client port: {client_port}")

    # Login
    message = {'type': 'login',
               'source': '',
               'destination': '',
               'content': 'login'}

    # start receiving messages from other clients (make sure they are authenticated with us)
    receive_message_thread = threading.Thread(target=receive_messages, args=(client_socket,), daemon=True)
    receive_message_thread.start()

    while True:
        command = input("+> ")
        if command == 'list':
            print("Executing 'list' command")
            # FIXME: Call function to list users
            # Send LIST command
        elif command.startswith('send'):
            # Parse send command
            _, recipient, content = command.split(' ', 2)
            # Send MESSAGE command
            # send(client_socket, addr, message)
        else:
            print("Invalid command or syntax. Please use 'list' or 'send <user> <message>'.")


if __name__ == "__main__":
    main()

# client.py
# ~client automatically chooses open port~

# --> enter username:
# andrew
# --> enter password:
# password

# ~ attempts mutual auth with KDC to get session key ~

...

# user can enter "list" or "send <user_id> <message>" commands

# send amanda "hello"
