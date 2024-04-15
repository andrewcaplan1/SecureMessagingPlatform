#!/usr/bin/env python3
import json
import selectors
import time
from node import Node, p
import os
import sys
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
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
                self.sel.unregister(c_socket)
                c_socket.close()
            else:
                received_json_data = json.loads(recv_data.decode('utf-8'))
                print(received_json_data)
                self.delegate_request(c_socket, received_json_data)
                # response = json.dumps(self.delegate_request(c_socket, received_json_data)).encode('utf-8')
                # c_data.outb += response

    # What is the query asking? Respond accordingly and tell the user if the action is
    # successful or not.
    def delegate_request(self, c_socket, json_request):
        src_usr = json_request['src']
        print(f"KDC received request '{json_request['type']}' from '{src_usr}'")

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
                self.message_auth(json_request['tgt'], json_request['tgt_iv'], json_request['iv'], json_request)
            else:
                self.send(c_socket, 'ERROR', content='Must authenticate first')

        elif json_request['type'] == 'LIST':
            # check authentication status, return response accordingly
            if self.user_info['src'] == 'authenticated':
                self.send(c_socket, 'LIST', users=self.user_info.keys())

        else:
            # unsupported request type
            self.send(c_socket, 'ERROR', content='Request type must be SIGN-IN, MSG-AUTH, or LIST')

        # FIXME: need outb?
        # return response

    # TGT --> ticket-to-B
    def message_auth(self, tgt, tgt_iv, shared_iv, json_request):

        tgt_bytes = base64.standard_b64decode(tgt)
        tgt_iv_bytes = base64.standard_b64decode(tgt_iv)
        tgt_text = self.decrypt(tgt_iv_bytes, self.master_key, tgt_bytes)
        print(tgt_text)
        tgt_list = list(tgt_text.decode('utf-8'))
        print(tgt_list)
        # FIXME: check tgt expiration

        # KDC validates TGT (also makes sure B is logged in and authenticated)
        # KDC creates new session key KAB between A and B
        # SB-KDC {A, timestamp, ticket-to-B-expiration, KAB, KAB-expiration}
        # KDC → WS: Ticket-to-B=SB-KDC{A, TS, TTB-Expiration, KAB, KAB-Expiration}, SA-KDC{B, TS, KAB-Expiration, KAB}
        pass

    def get_user_pw_hash(self, user):
        with open('kdc_database.json', "r") as jsonFile:
            db = json.load(jsonFile)

        print(db)
        if user in db:
            print("USER IN DATABASE: ", user, db[user])
            return db[user]
        else:
            # TODO: delete this password thingy
            print("user not in database, making their password HardPasssord123")
            digest = hashes.Hash(hashes.SHA256())
            digest.update('HardPassword123'.encode('utf-8'))
            pass_hash = digest.finalize()
            db.update({user: base64.standard_b64encode(pass_hash).decode('utf-8')})

        with open('kdc_database.json', "w") as jsonFile:
            json.dump(db, jsonFile)

        return db[user]

    # Signs into the server with this client's username.
    def sign_in_response(self, c_socket, src_usr, json_request):
        print("in sign in response (in KDC): ", json_request)

        # compute KDC side of DH
        dh_private = int.from_bytes(os.urandom(2048), 'big')  # a
        base64_pw_hash = self.get_user_pw_hash(src_usr)

        user_pw_hash = int.from_bytes(base64.standard_b64decode(base64_pw_hash), 'big')

        half_key = self.half_diffie_hellman(user_pw_hash, dh_private)  # g^a mod p

        # compute shared session key
        other_half = json_request['half_key']
        shared_key = (pow(other_half, dh_private, p)).to_bytes(32, 'big')
        print("shared key: ", shared_key)
        iv = os.urandom(16)  # initialization vector for CBC mode

        # store user's authentication state
        if src_usr not in self.user_info:
            self.user_info[src_usr] = {
                "address": c_socket.getpeername(),
                "last_step_received": "init-auth-req",
                "status": "unauthenticated",
                # "shared_key_expiration": "time of key gen + 20 min or so?",
                "shared_key": shared_key
            }
        else:
            self.user_info["address"] = c_socket.getpeername()
            self.user_info[src_usr]["last_step_received"] = "init-auth-req"
            self.user_info[src_usr]["shared_key"] = shared_key
            self.user_info[src_usr]["status"] = "unauthenticated"
            # self.user_info[src_usr]["shared_key_expiration"] = "new expiration"
            
        # encrypt timestamp with shared key
        bytes_timestamp = int(time.time()).to_bytes(32, 'big')
        encrypted_timestamp = self.encrypt(iv, shared_key, bytes_timestamp)
        challenge = os.urandom(16)
        encrypted_challenge = self.encrypt(iv, shared_key, challenge)

        self.send(c_socket, 'SIGN-IN', half_key=half_key, time=encrypted_timestamp, chal=encrypted_challenge,
                  iv=iv, protocol_step='init-auth-resp')

    def challenge_response(self, c_socket, src_usr, json_request):
        print("in challenge response (in KDC): ", json_request)

        # get shared key
        if src_usr not in self.user_info:
            print("User has not begun authentication process, restart and try again")
            sys.exit(1)
        elif (self.user_info[src_usr]["last_step_received"] == "init-auth-req"
              and json_request['protocol_step'] == "init-chal-resp"):

            shared_key = self.user_info[src_usr]["shared_key"]

            # check timestamp
            if self.decrypt_check_time(json_request['iv'], json_request['time'], shared_key):
                print("Timestamp valid, proceed with authentication")

                # prove knowledge
                bytes_timestamp = int(time.time()).to_bytes(32, 'big')
                ts_iv = os.urandom(16)
                encrypted_timestamp = self.encrypt(ts_iv, self.user_info[src_usr]['shared_key'], bytes_timestamp)

                # create TGT for user
                tgt_iv = os.urandom(16)
                content = str([src_usr, c_socket.getpeername(), time.time() + 3000])
                tgt = self.encrypt(tgt_iv, self.master_key, content.encode('utf-8'))
                
                self.send(c_socket, 'SIGN-IN', tgt=tgt, tgt_iv=tgt_iv, time=encrypted_timestamp, iv=ts_iv,
                          protocol_step='init-final')

                self.user_info[src_usr]["status"] = "authenticated"
                self.user_info[src_usr]["last_step_received"] = "init-chal_resp"
                self.user_info[src_usr]["auth_time"] = time.time()

            else:
                print("Timestamp invalid, aborting authentication")
                self.send(c_socket, 'ERROR', content='Out of date timestamp')


if __name__ == "__main__":
    with open('config.json') as f:
        server_info = json.load(f)

    kdc = KDC(server_info["KDC_HOST"], server_info["KDC_PORT"])
    kdc.run_server()
