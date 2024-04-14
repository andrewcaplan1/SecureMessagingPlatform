#!/usr/bin/env python3
import math
import selectors
import socket
import json
import os
import subprocess
import sys
import time

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from node import Node, p


#
# message = {'type': ['SIGN-IN', 'MESSAGE_AUTH' 'LIST', 'MESSAGE'],
#            'message_header' : ['init-auth-req', 'init-auth-resp', 'init-chall-resp', 'init-final']
#            'source': '(SENDER IP, SENDER PORT)',
#            'destination': '(DESTINATION IP, DESTINATION PORT',
#            'content': 'MESSAGE CONTENT'}


class Client(Node):

    def __init__(self, client_host, client_port, server_host, server_port, user, pw):
        super().__init__(client_host, client_port, user)
        self.password = pw

        # TCP socker for communicating with the KDC
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.connect((server_host, server_port))

        self.tgt = None  # ticket-granting-ticket
        self.keys = {}  # map from user/kdc to shared key

    # Signs into the server with this client's username.
    def sign_in(self):
        # int.frombytes(os.urandom(2048), 'big')
        dh_private = int.from_bytes(os.urandom(2048), 'big')  # a
        half_key = self.half_diffie_hellman(self.password, dh_private)  # g^a mod p
        self.send(self.server_sock, 'SIGN-IN', half_key, protocol_step='init-auth-req')

        sign_in_response = self.receive(self.server_sock)
        if sign_in_response and sign_in_response['protocol_step'] == 'init-auth-resp':
            # computing the shared session key
            self.keys['kdc'] = pow(sign_in_response['content'], dh_private, p)
        else:
            print("Did not receive SIGN-IN response from server")
            sys.exit(1)
        # FIXME: encrypt timestamp with the shared key
        challenge = self.encrypt(self.keys['kdc'], time.time())  # encrypts timestamp with session key
        self.send(self.server_sock, 'SIGN-IN', time=challenge, protocol_step='init-chal-1')
        # FIXME: should entire message be encrypted or just challenge?

    def receive(self, socket):
        packet_raw = socket.recv(1024)
        if packet_raw:
            return json.loads(packet_raw.decode())
        else:
            return None

    def process_command(self, user_input):
        parsed_input = user_input.split()
        command = parsed_input[0]
        if command == 'LIST':
            # FIXME: should list
            self.send(self.server_sock, 'list')
        elif command == 'MESSAGE':
            dest_user = parsed_input[1]
            if dest_user in self.user_socks:
                # already authenticated with dest user, so we can send message directly
                self.send(self.user_socks[dest_user], 'message', ' '.join(parsed_input[2:]))
                # FIXME: ' '.join erases the user's existing whitespace characters
            else:
                self.send(self.server_sock, 'message-auth', [dest_user, self.tgt])
                kdc_resp = self.receive(self.server_sock)
                if kdc_resp:
                    raw_resp = self.decrypt(kdc_resp['iv'], self.keys['kdc'], kdc_resp['content'])
                    json_resp = json.loads(raw_resp)
                    if valid_time(json_resp['time'], time.time()):
                        if kdc_resp['type'] == 'message-auth':
                            ticket = kdc_resp['ticket']
                            shared_key = kdc_resp['key']
                            shared_key_dest = kdc_resp['key_user']
                            friend_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            friend_sock.connect((kdc_resp['host'], kdc_resp['port']))
                            self.send(friend_sock, '')
                            # FIXME: make sure that shared_key_dest is the same as dest_user
                        else:
                            # FIXME: add better error handling... what to do when unexpected response type?
                            pass
                    else:
                        # FIXME: invalid timestamp, should we try again or ignore?
                        print("Received message with outdated timestamp")
                else:
                    print("KDC is unresponsive")
        else:
            print(f"Huh? Workstation does not recognize the command {command}")

    def run_client(self):
        self.sign_in()
        print(f"Signed in as '{self.username}'")

        try:
            while True:
                # command = input_stream.readline()
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
            # self.listen_sock.close()

    # Read the client's query and respond accordingly.
    def service_client(self, key, mask):
        c_socket = key.fileobj
        c_socket.setblocking(False)
        # FIXME: need this?
        # c_data = key.data

        # ready to read data from client
        if mask & selectors.EVENT_READ:
            recv_data = c_socket.recv(1024)

            # received no data --> bail out because client closed socket
            if not recv_data:
                self.sel.unregister(c_socket)
                c_socket.close()
            else:
                json_data = json.loads(recv_data.decode('utf-8'))
                socket_info = c_socket.getpeername()
                print(f"<From {socket_info[0]}:{socket_info[1]}:{json_data['src']}>: "
                      f"{json_data['content']}")


if __name__ == "__main__":
    username = input("Enter your username:")
    password = input("Enter your password:")
    with open('config.json') as f:
        config_file = json.load(f)

    client = Client(config_file["CLIENT_HOST"],
                    config_file["CLIENT_PORT"],
                    config_file["KDC_HOST"],
                    config_file["KDC_PORT"],
                    username,
                    password)
    client.run_client(sys.stdin)

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
