#!/usr/bin/env python3
import selectors
import socket
import json
import os
import sys
import time
import base64
import io

from node import Node, p


# message = {'type': ['SIGN-IN', 'MESSAGE_AUTH' 'LIST', 'MESSAGE'],
#            'message_header' : ['init-auth-req', 'init-auth-resp', 'init-chal-resp', 'init-final']
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
        self.user_socks = {}  # map of username to socket

        self.tgt = None  # ticket-granting-ticket
        self.keys = {}  # map from user/kdc to shared key
        # { user: (shared_key,expiration) }

        self.sel.register(sys.stdin, selectors.EVENT_READ)

        self.tgt = None
        self.tgt_iv = None

    # Signs into the server with this client's username.
    def sign_in(self):
        # initial authentication request
        dh_private = int.from_bytes(os.urandom(2048), 'big')  # a
        half_key = self.hash_and_diffie_hellman(self.password, dh_private)  # g^a mod p
        self.send(self.server_sock,
                  'SIGN-IN',
                  half_key=half_key,
                  protocol_step='init-auth-req',
                  listen_sock=self.listen_sock.getsockname())

        # receive initial authentication response
        sign_in_response = self.receive(self.server_sock)
        print(sign_in_response)
        # compute and store KDC shared session key
        if sign_in_response and sign_in_response['protocol_step'] == 'init-auth-resp':
            # computing the shared session key
            shared_key = (pow(sign_in_response['half_key'], dh_private, p)).to_bytes(32, 'big')
            self.keys['kdc'] = (shared_key, sign_in_response['key_exp'])
        else:
            print("Did not receive SIGN-IN response from server")
            sys.exit(1)
        print(f"Shared key with KDC: {self.keys['kdc']}")

        # check timestamp
        try:
            if self.decrypt_check_time(sign_in_response['iv'], sign_in_response['time'], self.keys['kdc'][0]):
                print("Timestamp valid, proceed with authentication")
            else:
                print("Timestamp invalid, Attempt to login again")
                return self.reset_login()
        except ValueError:
            print("Incorrect password")
            return self.reset_login()

        # encrypt timestamp challenge with the shared key
        bytes_timestamp = int(time.time()).to_bytes(32, 'big')
        iv = os.urandom(16)  # initialization vector for CBC mode
        challenge = self.encrypt(iv, self.keys['kdc'][0], bytes_timestamp)

        # send challenge to KDC
        self.send(self.server_sock, 'SIGN-IN', iv=iv, time=challenge, protocol_step='init-chal-resp')

        # receive tgt response
        tgt_response = self.receive(self.server_sock)

        # decrypt tgt response
        if tgt_response and tgt_response['protocol_step'] == 'init-final':
            self.tgt = tgt_response['tgt']  # already base64 encoded b/c it's from sent msg
            self.tgt_iv = tgt_response['tgt_iv']
            timestamp_challenge = tgt_response['time']
            timestamp_challenge_iv = tgt_response['iv']

            # decrypt tgt
            if self.decrypt_check_time(timestamp_challenge_iv, timestamp_challenge, self.keys['kdc'][0]):
                print("timestamp valid, authentication success")
            else:
                print("too slow! timestamp invalid, aborting authentication")

    def reset_login(self):
        self.keys.clear()
        self.username = input("Enter your username: ")
        self.password = input("Enter your password: ")
        return self.sign_in()

    def receive(self, socket):
        packet_raw = socket.recv(1024)
        if packet_raw:
            return json.loads(packet_raw.decode())
        else:
            return None

    def process_command(self, user_input):
        parsed_input = user_input.readline().strip().split(' ', 2)
        command = parsed_input[0]
        if command == 'logout':
            logout_message, iv = self.encrypt_list([self.username, time.time()], self.keys['kdc'][0])
            self.send(self.server_sock, "LOGOUT", message=logout_message, iv=iv)
            response = self.receive(self.server_sock)
            print(response['content'])
            return exit(0)
        elif command == 'list':
            self.send(self.server_sock, 'LIST')
            resp = self.receive(self.server_sock)
            if resp:
                print(f"Signed in users: {', '.join(resp['users'])}")
            else:
                print("KDC did not respond to LIST request")
        elif command == 'send':
            _, dest_user, message_content = parsed_input
            # check if we can straight up send a message to a user that is already authed
            if (dest_user in self.keys and self.check_time(self.keys[dest_user][1], timeout=3000)
                and self.keys[dest_user][0]) and self.user_socks[dest_user]:

                # already authenticated with dest user, so we can send message directly
                iv = os.urandom(16)
                print("HELLO")
                print(type(self.keys[dest_user][0]))
                print(self.keys[dest_user][0])
                ciphertext = self.encrypt(iv, self.keys[dest_user][0], message_content.encode('utf-8'))
                self.send(self.user_socks[dest_user], 'MESSAGE', message=ciphertext, iv=iv)
            else:
                # check that we actually have a TGT to get Ticket-to-client
                if not self.tgt or not self.tgt_iv:
                    print("No ticket-granting-ticket available, authentication failed")
                    # FIXME: maybe try to sign in again?
                    return

                # encrypt list of destination user and timestamp with KDC shared key
                encrypted_list, enc_iv = self.encrypt_list([dest_user, time.time()], self.keys['kdc'][0])

                # send message-auth request to KDC
                self.send(self.server_sock, 'MSG-AUTH', content=encrypted_list, content_iv=enc_iv, tgt=self.tgt,
                          tgt_iv=self.tgt_iv)

                kdc_resp = self.receive(self.server_sock)

                if kdc_resp:
                    if kdc_resp['type'] == 'ERROR':
                        print(kdc_resp['content'])
                    else:
                        dest_user, dest_info, key_ab, key_ab_exp, ts \
                            = self.decrypt_list(kdc_resp['key_info'], kdc_resp['key_info_iv'], self.keys['kdc'][0])

                        bytes_key_ab = base64.standard_b64decode(key_ab)
                        print("KEY_AB: ", key_ab, "\nbytes_key_ab: ", bytes_key_ab)
                        # store key_ab in keys dict
                        self.keys[dest_user] = (bytes_key_ab, key_ab_exp)

                        # check that the timestamp is valid
                        if self.check_time(ts):
                            # create a new socket for the destination user
                            dest_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            dest_sock.connect((dest_info[0], dest_info[1]))
                            self.user_socks[dest_user] = dest_sock

                            # encrypt message with shared key
                            msg_list = [self.username, message_content, time.time()]
                            enc_msg, msg_iv = self.encrypt_list(msg_list, self.keys[dest_user][0])

                            self.send(dest_sock, 'MSG-REQ', ttb=kdc_resp['ttb'], ttb_iv=kdc_resp['ttb_iv'],
                                      message=enc_msg, message_iv=msg_iv)
                            # FIXME: make sure that shared_key_dest is the same as dest_user
                        else:
                            # FIXME: invalid timestamp, should we try again or ignore?
                            print("Received message with outdated timestamp, ignoring...")
                else:
                    print("KDC is unresponsive")
        else:
            print(f"Huh? Workstation does not recognize the command {command}")

    def run_client(self):
        self.sign_in()
        print(f"Signed in as '{self.username}'")

        try:
            while True:
                client_requests = self.sel.select(timeout=None)
                # loop through sockets
                for key, mask in client_requests:
                    if isinstance(key.fileobj, io.TextIOWrapper):
                        self.process_command(key.fileobj)
                    elif key.data is None:
                        # found new client from server's listening socket --> accept connection
                        self.register_client(key.fileobj)
                    else:
                        # existing client --> do what they request
                        self.service_client(key, mask)
        except KeyboardInterrupt:
            print("Stopping server...")
        finally:
            # close all sockets
            for key in self.user_socks:
                self.user_socks[key].close()
            self.sel.close()
            self.listen_sock.close()
            self.server_sock.close()

    # Read the client's query and respond accordingly.
    def service_client(self, key, mask):
        c_socket = key.fileobj
        c_socket.setblocking(False)
        # FIXME: need this?
        c_data = key.data

        # ready to read data from client
        if mask & selectors.EVENT_READ:
            recv_data = c_socket.recv(1024)

            # received no data --> bail out because client closed socket
            if not recv_data:
                # print(f"Closing connection to {c_data.addr}")
                # self.sel.unregister(c_socket)
                # c_socket.close()
                pass
            else:
                json_data = json.loads(recv_data.decode('utf-8'))
                self.delegate_request(c_socket, json_data)
                # socket_info = c_socket.getpeername()
                # print(f"<From {socket_info[0]}:{socket_info[1]}:{json_data['src']}>: "
                #       f"{json_data['content']}")

    def delegate_request(self, c_socket, json_request):
        # if we are receiving a new message request from another client
        if json_request['type'] == 'MSG-REQ':
            # decrypt ticket to me
            ttb = json_request['ttb']
            ttb_iv = json_request['ttb_iv']
            ttb_user, user_addr, ttb_exp, shared_key, shared_key_exp = self.decrypt_list(ttb, ttb_iv,
                                                                                         self.keys['kdc'][0])

            bytes_shared_key = base64.standard_b64decode(shared_key)
            # print("TICKET-TO-ME: shared-key: ", shared_key, "\nbytes_shared_key", bytes_shared_key)

            # check if ticket-to-me is valid, and if shared key is still valid
            if self.check_time(ttb_exp) and self.check_time(shared_key_exp, timeout=3000):
                # FIXME: check if shared_key is expired
                # store shared key in keys dict
                self.keys[ttb_user] = (bytes_shared_key, shared_key_exp)

                # decrypt message
                msg_user, message, ts = self.decrypt_list(json_request['message'], json_request['message_iv'],
                                                          bytes_shared_key)

                # check if message time is valid, usernames from ttb and message match
                if self.check_time(ts) and ttb_user == msg_user:
                    dest_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    dest_sock.connect((user_addr[0], user_addr[1]))
                    self.user_socks[msg_user] = dest_sock

                    # display message
                    print(f"<From {msg_user}>: {message}")
        if json_request['type'] == 'MESSAGE':
            # decrypt message
            message, iv = json_request['message'], json_request['iv']

            base64_message = base64.standard_b64decode(message)
            base64_iv = base64.standard_b64decode(iv)

            if json_request['src'] in self.keys and self.keys[json_request['src']][0]:
                decrypted_message = self.decrypt(base64_iv, self.keys[json_request['src']][0], base64_message).decode(
                    'utf-8')
                print(f"Received message: {decrypted_message}")


if __name__ == "__main__":
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    with open('config.json') as f:
        config_file = json.load(f)

    client = Client(config_file["CLIENT_HOST"],
                    config_file["CLIENT_PORT"],
                    config_file["KDC_HOST"],
                    config_file["KDC_PORT"],
                    username.lower(),
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
