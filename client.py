#!/usr/bin/env python3
import math
import selectors
import socket
import json
# import cryptography
# from cryptography.hazmat.primitives import hashes

from node import Node


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

    # Signs into the server with this client's username.
    def sign_in(self):

        # FIXME: replace content with SPEKE or SRP
        self.send(self.server_sock, 'SIGN-IN', 'Diffie Helman')

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
        packet_raw = self.server_sock.recv(1024)
        if packet_raw:
            packet_json = json.loads(packet_raw.decode())
            return packet_json
        else:
            return None

    def speke(self, password):
        # digest = hashes.Hash(hashes.SHA256())
        # digest.update(password)
        # pass_hash = digest.finalize()
        # # https://datatracker.ietf.org/doc/rfc3526/?include_text=1
        # p = int(2 ** 2048 - 2 ** 1984 - 1 + 2 ^ 64 * ((2 ** 1918 * math.pi) + 124476))
        # g = (pass_hash ** 2) % p  # same as pow(pass_hash, 2, p)
        pass

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
            # self.listen_sock.close()

    # Read the client's query and respond accordingly.
    def service_client(self, key, mask):
        c_socket = key.fileobj
        c_socket.setblocking(False)
        c_data = key.data

        # ready to read data from client
        if mask & selectors.EVENT_READ:
            recv_data = c_socket.recv(1024)

            # received no data --> bail out because client closed socket
            if not recv_data:
                self.sel.unregister(c_socket)
                c_socket.close()
            else:
                json_data = json.loads(recv_data.decode('utf-8'))
                # response = json.dumps(self.delegate_request(c_socket, json_data)).encode('utf-8')
                # c_data.outb += response
                print(json_data)


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
