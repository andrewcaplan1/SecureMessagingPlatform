#!/usr/bin/env python3
import math
import selectors
import socket
import json
import time

from cryptography.hazmat.primitives import hashes

from node import Node


#
# message = {'type': ['SIGN-IN', 'MESSAGE_AUTH' 'LIST', 'MESSAGE'],
#            'message_header' : ['init-auth-req', 'init-auth-resp', 'init-chall-resp', 'init-final']
#            'source': '(SENDER IP, SENDER PORT)',
#            'destination': '(DESTINATION IP, DESTINATION PORT',
#            'content': 'MESSAGE CONTENT'}


class Client(Node):

    def __init__(self, client_host, client_port, server_host, server_port, user, pw):
        super().__init__(client_host, client_port)
        self.username = user
        self.password = pw

        # TCP socker for communicating with the KDC
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.connect((server_host, server_port))

    # Signs into the server with this client's username.
    def sign_in(self):

        # FIXME: replace content with SPEKE or SRP
        self.send(self.listen_sock, self.server_sock, 'SIGN-IN', 'Diffie Helman')

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

    def send(self, src_sock, dest_sock, msg_type, content):
        src_sock_info = src_sock.getpeername()
        json_request = {
            'type': msg_type,
            'src': f'{src_sock_info[0]}:{src_sock_info[1]}:{self.username}',
            'dest': dest_sock.getsockname(),
            'time': time.time(),
            'content': content
        }
        print(f"Sending message: {json_request}")
        dest_sock.send(json.dumps(json_request).encode('utf-8'))

    def receive(self):
        packet_raw = self.server_sock.recv(1024)
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

    # Function to handle incoming messages
    def receive_messages(self):
        print("Receiving message...")
        while True:
            try:
                data = self.server_sock.recv(4096)
                message = json.loads(data.decode('utf-8'))
                return message
            except socket.timeout:
                continue

    def run_client(self):
        self.sign_in()

        try:
            while True:
                client_requests = self.sel.select(timeout=None)
                # loop through sockets
                for key, mask in client_requests:
                    if key.data is None:
                        # found new client from server's listening socket --> accept connection
                        self.register_client(key.fileobj)
                    else:
                        # existing client --> do what they request
                        self.service_client(key, mask)
        except KeyboardInterrupt:
            print("Stopping server...")
        finally:
            # close all sockets
            self.sel.close()
            self.listen_sock.close()


if __name__ == "__main__":
    username = input("Enter your username:")
    password = input("Enter your password:")
    with open('config.json') as f:
        config_file = json.load(f)

    client = Client(config_file["KDC_HOST"],
                    config_file["KDC_PORT"],
                    config_file["CLIENT_HOST"],
                    config_file["CLIENT_PORT"],
                    username,
                    password)
    client.run_client()

# client.py
# ~client automatically chooses open port~

# --> enter username:
# andrew
# --> enter password:
# password

# ~ attempts mutual auth with KDC to get session key ~

# ...

# user can enter "list" or "send <user_id> <message>" commands

# send amanda "hello"
