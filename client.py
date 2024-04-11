#!/usr/bin/env python3
import math
import socket
import argparse
import json
import threading
import sys
from cryptography.hazmat.primitives import hashes

message = {'type': ['SIGN-IN', 'MESSAGE_AUTH' 'LIST', 'MESSAGE'],
           # 'subtype'? like msg_auth_request, msg_auth_response, etc.
           'source': '(SENDER IP, SENDER PORT)',
           'destination': '(DESTINATION IP, DESTINATION PORT',
           'content': 'MESSAGE CONTENT'}


class Client:

    def __init__(self, server_host, server_port, user, pw):
        self.username = user
        self.password = hashes.Hash(hashes.SHA256())
        # create TCP socket for talking to server
        self.server_addr = (server_host, server_port)
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.connect(self.server_addr)

        # create UDP socket for sending to other clients
        self.friend_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


        # create UDP socket for receiving data from other clients
        self.client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client_sock.bind((UDP_IP, UDP_PORT))
        self.sign_in()

    # Called at initialization. Signs into the server with this client's username.
    def sign_in(self):
        sign_in_request = {'type': 'SIGN-IN', 'user': self.username}
        self.server_sock.dumps(sign_in_request).encode('utf-8'))
        sign_in_response = self.receive()

        if sign_in_response:
            if 'ERROR' == sign_in_response['status']:
                print('Failed to sign in with error from server: ' + sign_in_response['message'])
                exit(1)
            else:
                print(f"Signed in as '{self.username}'")
        else:
            print("Server failed to sign in with unknown server error")

    def speke(self, password):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(password)
        pass_hash = digest.finalize()
        # https://datatracker.ietf.org/doc/rfc3526/?include_text=1
        p = int(2 ** 2048 - 2 ** 1984 - 1 + 2 ^ 64 * ((2 ** 1918 * math.pi) + 124476))
        g = (pass_hash ** 2) % p  # same as pow(pass_hash, 2, p)

    # Process command line input and form a JSON query to send to the server.
    def send(self, user_input):
        input_tokens = user_input.split()
        if len(input_tokens) > 0:
            if input_tokens[0] == "list":
                self.server_sock.send(json.dumps({'type': 'LIST', 'user': self.username})
                                      .encode('utf-8'))

            elif input_tokens[0] == "send":
                message_start = user_input.index(input_tokens[1]) + len(input_tokens[1])
                msg_content = user_input[message_start:].strip()
                message = {'type': 'MESSAGE',
                           'user': self.username,
                           'dst_usr': input_tokens[1],
                           'message': msg_content}
                self.server_sock.send(json.dumps(message).encode('utf-8'))
            else:
                print("ERROR: Unrecognized command")
                # re-prompt...
                sys.stdout.write("+> ")

    # Function to handle incoming messages
    def receive_messages(self):
        print("Receiving message...")
        while True:
            try:
                data = self.server_sock.recv(4096)
                message = json.loads(data.decode('utf-8'))
                return message['content']
            except socket.timeout:
                continue

    def run_client(self):
        # print(f"Client port: {client_port}")

        # Login
        message = {'type': 'login',
                   'source': '',
                   'destination': '',
                   'content': 'login'}
        self.server_sock.send(json.dumps({'type': 'SIGN-IN', 'user': self.username}).encode('utf-8'))
        self.server_sock.send(json.dumps({'type': 'SIGN-IN', 'user': self.username}).encode('utf-8'))
        # self.server_sock.send(json.dumps(message).encode('utf-8'))
        receive_message_thread = threading.Thread(target=self.receive_messages, daemon=True)
        receive_message_thread.start()
        while True:
            command = input("+> ")
            self.send(command)


        # # start receiving messages from other clients (make sure they are authenticated with us)
        # receive_message_thread = threading.Thread(target=self.receive_messages, args=(client_socket,), daemon=True)
        # receive_message_thread.start()
        #
        # # after logging in, the user can list users or send messages
        # while True:
        #     command = input("+> ")
        #     if command == 'list':
        #         print("Executing 'list' command")
        #         # FIXME: Call function to list users
        #         # Send LIST command
        #     elif command.startswith('send'):
        #         # Parse send command
        #         _, recipient, content = command.split(' ', 2)
        #         # Send MESSAGE command
        #         # send(client_socket, addr, message)
        #     else:
        #         print("Invalid command or syntax. Please use 'list' or 'send <user> <message>'.")


if __name__ == "__main__":
    username = input("Enter your username:")
    password = input("Enter your password:")
    with open('config.json') as f:
        server_info = json.load(f)

    client = Client(server_info["KDC_HOST"], server_info["KDC_PORT"], username, password)
    client.run_client()

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
