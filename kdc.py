#!/usr/bin/env python3
import json
import selectors
import time
from node import Node, p
import os
import sys
from cryptography.hazmat.primitives import hashes
import base64


class KDC(Node):

    def __init__(self, host, port):
        super().__init__(host, port, "KDC")

        # FIXME (with the labels for each step)
        self.user_info = {}  # map of user to authentication status ["authenticated", "unauthenticated"]
        # user_info example:
        # {
        #     "address": "(user_host, user_port)",
        #     "last_step_received": "init-auth-req",
        #     "status": "unauthenticated",
        #     # "shared_key_expiration": "time of key gen + 20 min or so?",
        #     "shared_key": shared_key
        # }

        self.master_key = os.urandom(32)  # for encrypting TGTs

        print("KDC Server Initialized...")

    # Main method, continuously accepts new sign-on requests and responds to existing
    # clients' queries.
    def run_server(self):
        try:
            while True:
                client_requests = self.sel.select(timeout=1)
                # loop through sockets
                for key, mask in client_requests:
                    if key.data is None:
                        # found new client from server's listening socket --> accept connection
                        self.register_client(key.fileobj)

                    else:
                        # existing client --> do what they request
                        # key.fileobj.getpeername()
                        # self.user_info
                        # {
                        #     "address": "(user_host, user_port)",
                        #     "last_step_received": "init-auth-req",
                        #     "status": "unauthenticated",
                        #     # "shared_key_expiration": "time of key gen + 20 min or so?",
                        #     "shared_key": shared_key
                        # }
                        self.service_client(key, mask)
        except KeyboardInterrupt:
            print("Stopping server...")
            self.listen_sock.close()
        finally:
            # close all sockets
            self.sel.close()

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
                print(f"Closing connection to {c_data.addr}")
                # FIXME: remove username from user_info, don't want to grant others ttb's
                self.sel.unregister(c_socket)
                c_socket.close()
            else:
                received_json_data = json.loads(recv_data.decode('utf-8'))
                # print(received_json_data)
                self.delegate_request(c_socket, received_json_data)

    # What is the query asking? Respond accordingly and tell the user if the action is
    # successful or not.
    def delegate_request(self, c_socket, json_request):
        src_usr = json_request['src']
        # print(f"KDC received request '{json_request['type']}' from '{src_usr}'")

        # handle sign-in request
        if json_request['type'] == 'SIGN-IN':
            # check what step of sign in the user is on
            if json_request['protocol_step'] == 'init-auth-req':
                self.sign_in_response(c_socket, src_usr, json_request)
            elif json_request['protocol_step'] == 'init-chal-resp':
                self.challenge_response(c_socket, src_usr, json_request)
            else:
                print("Bad SIGN-IN protocol step, exiting....")
                # FIXME: ignore instead of exit?
                sys.exit(1)

        # handle message-auth request
        elif json_request['type'] == 'MSG-AUTH':
            # checks if user is authenticated already
            if src_usr in self.user_info and self.user_info[src_usr]["status"] == "authenticated":
                self.message_auth(c_socket, json_request['tgt'], json_request['tgt_iv'],
                                  json_request['content'], json_request['content_iv'], src_usr)
            else:
                self.send(c_socket, 'ERROR', content='Must authenticate first')

        elif json_request['type'] == 'LIST':
            # check authentication status, return response accordingly
            if src_usr in self.user_info and self.user_info[src_usr]['status'] == 'authenticated':
                self.send(c_socket, 'LIST', users=list(self.user_info.keys()))
            else:
                self.send(c_socket, 'ERROR', content='User not authenticated')

        elif json_request['type'] == 'LOGOUT':
            if src_usr in self.user_info:
                del self.user_info[src_usr]
                self.send(c_socket, 'LOGOUT', content='Successfully logged out')
            else:
                self.send(c_socket, 'ERROR', content='User not authenticated')
        else:
            # unsupported request type
            self.send(c_socket, 'ERROR', content='Request type must be SIGN-IN, MSG-AUTH, or LIST')

    # TGT --> ticket-to-B
    def message_auth(self, c_socket, tgt, tgt_iv, content, content_iv, src_usr):
        # [src_usr, c_socket.getpeername(), time.time() + 3000]
        tgt_list = self.decrypt_list(tgt, tgt_iv, self.master_key)
        # print(tgt_list)

        # check tgt for validity
        if tgt_list[0] != src_usr:
            # print("tgt username does not match src_usr")
            self.send(c_socket, 'ERROR', content='tgt username does not match src_usr')
        elif tgt_list[1] != list(c_socket.getpeername()):
            # print("tgt address does not match client address")
            self.send(c_socket, 'ERROR', content='tgt address does not match client address')
        elif tgt_list[2] < time.time():
            print("tgt expired")
            self.send(c_socket, 'ERROR', content='tgt expired')
        else:
            # tgt is ok
            dest_user, timestamp = self.decrypt_list(content, content_iv, self.user_info[src_usr]['shared_key'])

            # check if user is authenticated
            if self.user_info[dest_user]['status'] != 'authenticated':
                self.send(c_socket, 'ERROR', content='Target user has not registered yet')
            # check if timestamp is valid
            elif not self.check_time(timestamp):
                print('Timestamp expired')
                self.send(c_socket, 'ERROR', content='message timestamp bad')
            else:
                # create ticket-to-B
                session_key_ab = os.urandom(32)
                base64_session_key_ab = base64.standard_b64encode(session_key_ab).decode('utf-8')

                kab_expiration = time.time() + 3000

                # [username, sender_address, expiration of ttb, session_key Kab, expiration Kab]
                ttb = [src_usr, self.user_info[src_usr]["address"], time.time() + 300, base64_session_key_ab,
                       kab_expiration]
                encrypted_ttb, ttb_iv = self.encrypt_list(ttb, self.user_info[dest_user]['shared_key'])

                key_info = [dest_user, self.user_info[dest_user]['address'], base64_session_key_ab,
                            kab_expiration, time.time()]

                encrypted_key_info, key_info_iv = self.encrypt_list(key_info,
                                                                    self.user_info[src_usr]['shared_key'])

                self.send(c_socket, 'MSG-AUTH', ttb=encrypted_ttb, ttb_iv=ttb_iv, key_info=encrypted_key_info,
                          key_info_iv=key_info_iv)

    def get_user_pw_hash(self, user):
        with open('kdc_database.json', "r") as jsonFile:
            db = json.load(jsonFile)

        if user in db:
            return db[user]
        else:
            return None

    # Signs into the server with this client's username.
    def sign_in_response(self, c_socket, src_usr, json_request):
        if src_usr in self.user_info and self.user_info[src_usr]["status"] == "authenticated":
            print("User already authenticated, logout first")
            self.send(c_socket, 'ERROR', content='User already authenticated, logout first')
            return

        # compute KDC side of DH
        dh_private = int.from_bytes(os.urandom(2048), 'big')  # a
        base64_pw_hash = self.get_user_pw_hash(src_usr)

        if base64_pw_hash is None:
            print("User not in database, try again with real credentials")
            self.send(c_socket, 'ERROR', content='message timestamp bad')

        user_pw_hash = int.from_bytes(base64.standard_b64decode(base64_pw_hash), 'big')

        half_key = self.half_diffie_hellman(user_pw_hash, dh_private)  # g^a mod p

        # compute shared session key
        other_half = json_request['half_key']
        shared_key = (pow(other_half, dh_private, p)).to_bytes(32, 'big')
        iv = os.urandom(16)  # initialization vector for CBC mode

        # store user's authentication state
        if src_usr not in self.user_info:
            self.user_info[src_usr] = {
                "address": json_request['listen_sock'],
                "last_step_received": "init-auth-req",
                "status": "unauthenticated",
                "shared_key": shared_key,
                "shared_key_exp": time.time() + 3000
            }
        else:
            self.user_info[src_usr]["address"] = json_request['listen_sock']
            self.user_info[src_usr]["last_step_received"] = "init-auth-req"
            self.user_info[src_usr]["shared_key"] = shared_key
            self.user_info[src_usr]["status"] = "unauthenticated"
            self.user_info[src_usr]["shared_key_expiration"] = time.time() + 3000

        # encrypt timestamp with shared key
        bytes_timestamp = int(time.time()).to_bytes(32, 'big')
        encrypted_timestamp = self.encrypt(iv, shared_key, bytes_timestamp)
        challenge = os.urandom(16)
        encrypted_challenge = self.encrypt(iv, shared_key, challenge)

        self.send(c_socket, 'SIGN-IN', half_key=half_key, time=encrypted_timestamp, chal=encrypted_challenge,
                  iv=iv, protocol_step='init-auth-resp', key_exp=self.user_info[src_usr]['shared_key_exp'])

    def challenge_response(self, c_socket, src_usr, json_request):
        # get shared key
        if src_usr not in self.user_info:
            print("User has not begun authentication process, restart and try again")
            # sys.exit(1)
        elif (self.user_info[src_usr]["last_step_received"] == "init-auth-req"
              and json_request['protocol_step'] == "init-chal-resp"):

            shared_key = self.user_info[src_usr]["shared_key"]

            try:
                # check timestamp
                if self.decrypt_check_time(json_request['iv'], json_request['time'], shared_key):
                    # prove knowledge
                    bytes_timestamp = int(time.time()).to_bytes(32, 'big')
                    ts_iv = os.urandom(16)
                    encrypted_timestamp = self.encrypt(ts_iv, self.user_info[src_usr]['shared_key'], bytes_timestamp)

                    tgt_list = [src_usr, c_socket.getpeername(), time.time() + 3000]
                    tgt, tgt_iv = self.encrypt_list(tgt_list, self.master_key)

                    print(f'User {src_usr} authenticated!')
                    self.send(c_socket, 'SIGN-IN', tgt=tgt, tgt_iv=tgt_iv, time=encrypted_timestamp, iv=ts_iv,
                              protocol_step='init-final')

                    self.user_info[src_usr]["status"] = "authenticated"
                    self.user_info[src_usr]["last_step_received"] = json_request['protocol_step']
                    self.user_info[src_usr]["auth_time"] = time.time()

                else:
                    print("Timestamp invalid, aborting authentication")
                    self.send(c_socket, 'ERROR', content='Out of date timestamp')
            except ValueError:
                print("Incorrect password")
                del self.user_info[src_usr]
        else:
            print("Bad protocol step order, try again")


if __name__ == "__main__":
    with open('config.json') as f:
        server_info = json.load(f)

        kdc = KDC(server_info["KDC_HOST"], server_info["KDC_PORT"])
        kdc.run_server()
