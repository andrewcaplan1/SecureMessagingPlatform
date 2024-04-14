#!/usr/bin/env python3
import json
import selectors
import time
from node import Node


class KDC(Node):

    def __init__(self, host, port):
        super().__init__(host, port, "KDC")

        # FIXME (with the labels for each step)
        self.user_auth_states = {}  # map of user to authentication status ["authenticated", "unauthenticated"]
        # {"username": {
        #     "address": "(user_host, user_port)
        #     "last_step_completed": "init-auth-req",
        #     "status": "unauthenticated",
        #     "shared_key_expiration": "time of key gen + 20 min or so?",
        #     "shared_key": "shared key between KDC and user"}
        # }

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
                response = json.dumps(self.delegate_request(c_socket, received_json_data)).encode('utf-8')
                c_data.outb += response

    # What is the query asking? Respond accordingly and tell the user if the action is
    # successful or not.
    def delegate_request(self, c_socket, json_request):
        src_usr = json_request['src']
        print(f"KDC received request '{json_request['type']}' from '{src_usr}'")

        # response = {
        #     'type': 'SIGN-IN',
        #     'step': 'init-auth-resp',
        #     'src': self.username,
        #     'dest': c_socket.getsockname(),
        #     'time': time.time(),
        #     'content': "hello, sir"
        # }

        # handle sign-in request
        if json_request['type'] == 'SIGN-IN':
            # check what step of sign in the user is on
            if json_request['protocol_step'] == 'init-auth-req':
                self.sign_in_response(c_socket, src_usr, json_request)
            elif json_request['protocol_step'] == 'init-chall-resp':
                self.challenge_response(c_socket, src_usr, json_request)
            else:
                print("unkown SIGN-IN protocol step, exiting....")
                sys.exit(1)

        # handle message-auth request
        elif json_request['type'] == 'MESSAGE-AUTH':
            # checks if user is authenticated already
            if src_usr in self.user_auth_states and self.user_auth_states[src_usr]["status"] == "authenticated":
                self.message_auth(c_socket, src_usr, json_request)

            else:
                self.sign_in(c_socket, json_request)
        # else:
        #     print("error")
        #     # ERROR if client tries to do an action before signing in

        return response

    def get_user_pw_hash(self, user):
        with open('kdc_database.json', "r") as jsonFile:
            db = json.load(jsonFile)

        if user in db:
            return data[user]
        else:
            # TODO: delete this password thingy
            print("user not in database, making their password HardPasssord123")
            digest = hashes.Hash(hashes.SHA256())
            digest.update('HardPassword123'.encode('utf-8'))
            pass_hash = digest.finalize()
            db[user] = pass_hash

        with open('kdc_database.json', "w") as jsonFile:
            json.dump(db, jsonFile)

        return db[user]


    # Signs into the server with this client's username.
    def sign_in_response(self, c_socket, src_usr, json_request):
        print("in sign in response (in KDC)")

        # compute KDC side of DH
        dh_private = int.from_bytes(os.urandom(2048), 'big')  # a
        user_pw_hash = get_user_pw_hash(src_usr)

        half_key = self.half_diffie_hellman(user_pw_hash, dh_private)  # g^a mod p

        # compute shared session key
        other_half = json_request[content]
        
        shared_key = pow(other_half, dh_private, p)

        # init vector for encryption
        iv = os.urandom(16)

        # store user's authentication state
        if src_usr not in self.user_auth_states:
            self.user_auth_states[src_usr] = {
                "address": "(user_host, user_port)",
                "last_step_received": "init-auth-req",
                "status": "unauthenticated",
                # "shared_key_expiration": "time of key gen + 20 min or so?",
                "init_vector": iv,
                "shared_key": shared_key }
        else:
            self.user_auth_states[src_usr]["last_step_received"] = "init-auth-req"
            self.user_auth_states[src_usr]["shared_key"] = shared_key
            self.user_auth_states[src_usr]["status"] = "unauthenticated"
            self.user_auth_states[src_usr]["init_vector"] = iv
            # self.user_auth_states[src_usr]["shared_key_expiration"] = "new expiration"
        
        encrypted_timestamp = self.encrypt(iv, shared_key, timestamp)
        self.send(self.server_sock, 'SIGN-IN', half_key=half_key, encrypted_timestamp= encrypted_timestamp, iv=init_vector,
                  protocol_step='init-auth-resp')

        # sign_in_response = self.receive()
        # if sign_in_response and sign_in_response['protocol_step'] == 'init-auth-resp':
        #     # computing the shared session key
        #     self.kdc_key = pow(sign_in_response['content'], dh_private, p)
        # else:
        #     print("Did not receive SIGN-IN response from server")
        #     sys.exit(1)
        # # FIXME: encrypt timestamp with the shared key
        # challenge = self.encrypt(self.kdc_key, time.time())  # encrypts timestamp with session key
        # self.send(self.server_sock, 'SIGN-IN', challenge, protocol_step='init-chal-1')
        # # FIXME: should entire message be encrypted or just challenge?

    # Function to handle LIST command
    def list_command(self, client_addr, clients):
        online_users = list(clients.keys())
        message_to_send = f"Signed In Users: {', '.join(online_users)}"
        response = {'type': 'LIST', 'content': message_to_send}


if __name__ == "__main__":
    with open('config.json') as f:
        server_info = json.load(f)

    kdc = KDC(server_info["KDC_HOST"], server_info["KDC_PORT"])
    kdc.run_server()
