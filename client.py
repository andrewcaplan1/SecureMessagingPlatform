#!/usr/bin/env python3
import math
import socket
import argparse
import json
import threading
import sys
import time
from cryptography.hazmat.primitives import hashes


#
# message = {'type': ['SIGN-IN', 'MESSAGE_AUTH' 'LIST', 'MESSAGE'],
#            'message_header' : ['init-auth-req', 'init-auth-resp', 'init-chall-resp', 'init-final']
#            'source': '(SENDER IP, SENDER PORT)',
#            'destination': '(DESTINATION IP, DESTINATION PORT',
#            'content': 'MESSAGE CONTENT'}


class Client:

    def __init__(self, server_host, server_port, user, pw):
        self.username = user
        self.password = pw
        self.kdc_addr = (server_host, server_port)
        print("kdc addr: ", self.kdc_addr)
        # create TCP socket for initiating new connection and responding (EI. to KDC or to new client)
        self.init_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.init_sock.connect(self.kdc_addr)

        # create TCP socket for receiving new connections and responding (EI. from new client)
        # self.friend_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # self.friend_sock.bind(('localhost', 0))

        # the address of the client's friend socket on which we can receive/respond to new connections from other
        # clients
        # self.client_addr = self.friend_sock.getsockname()

        # Auths with the KDC using user/pw to sign in
        print("before sign-in")
        self.sign_in()

    # Called at initialization. Signs into the server with this client's username.
    def sign_in(self):
        # message = {'type': ['SIGN-IN', 'MESSAGE_AUTH' 'LIST', 'MESSAGE'],
        #            'message_header' : ['init-auth-req', 'init-auth-resp', 'init-chall-resp', 'init-final']
        #            'source': '(SENDER IP, SENDER PORT)',
        #            'destination': '(DESTINATION IP, DESTINATION PORT',
        #            'content': 'MESSAGE CONTENT'}
        sign_in_request = {
            'type': 'SIGN-IN',
            'header': 'init-auth-req',
            'source': self.username,
            'destination': self.kdc_addr,
            'timestamp': time.time(),
            'content': 'INPUT SPEKE DIFFIE HELLMAN HERE'}
        print("attempting send message")
        self.init_sock.send(json.dumps(sign_in_request).encode('utf-8'))
        print("message sent")
        sign_in_response = self.receive_messages()

        if sign_in_response:
            print(sign_in_response)
            # if 'ERROR' == sign_in_response['status']:
            #     print('Failed to sign in with error from server: ' + sign_in_response['message'])
            #     exit(1)
            # else:
            print(f"Signed in as '{self.username}'")
        else:
            print("Server failed to sign in with unknown server error")

    def receive(self):
        packet_raw = self.init_sock.recv(1024)
        if packet_raw:
            packet_json = json.loads(packet_raw.decode())
            return packet_json
        else:
            return None

    def speke(self, password):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(password)
        pass_hash = digest.finalize()
        # https://datatracker.ietf.org/doc/rfc3526/?include_text=1
        p = int(2 ** 2048 - 2 ** 1984 - 1 + 2 ^ 64 * ((2 ** 1918 * math.pi) + 124476))
        g = (pass_hash ** 2) % p  # same as pow(pass_hash, 2, p)

    # Process command line input and form a JSON query to send to the server.
    # def send(self, user_input):
    #     input_tokens = user_input.split()
    #     if len(input_tokens) > 0:
    #         if input_tokens[0] == "list":
    #             self.server_sock.send(json.dumps({'type': 'LIST', 'user': self.username})
    #                                   .encode('utf-8'))
    #
    #         elif input_tokens[0] == "send":
    #             message_start = user_input.index(input_tokens[1]) + len(input_tokens[1])
    #             msg_content = user_input[message_start:].strip()
    #             message = {'type': 'MESSAGE',
    #                        'user': self.username,
    #                        'dst_usr': input_tokens[1],
    #                        'message': msg_content}
    #             self.server_sock.send(json.dumps(message).encode('utf-8'))
    #         else:
    #             print("ERROR: Unrecognized command")
    #             # re-prompt...
    #             sys.stdout.write("+> ")

    # Function to handle incoming messages
    def receive_messages(self):
        print("Receiving message...")
        while True:
            try:
                data = self.init_sock.recv(4096)
                message = json.loads(data.decode('utf-8'))
                return message
            except socket.timeout:
                continue

    def run_client(self):
        # print(f"Client port: {client_port}")

        # Login
        message = {'type': 'login',
                   'source': '',
                   'destination': '',
                   'content': 'login'}

        # print(message)
        # self.init_sock.send(json.dumps({'type': 'SIGN-IN', 'source': self.username}).encode('utf-8'))
        # self.init_sock.send(json.dumps({'type': 'SIGN-IN', 'source': self.username}).encode('utf-8'))
        # self.server_sock.send(json.dumps(message).encode('utf-8'))
        # receive_message_thread = threading.Thread(target=self.receive_messages, daemon=True)
        # receive_message_thread.start()
        while True:
            command = input("+> ")
            print(command)
            # self.send(command)

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
