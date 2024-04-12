#!/usr/bin/env python3
import json
import selectors
import socket
import types

from node import Node


class KDC(Node):

    def __init__(self, host, port):
        super().__init__(host, port)

        # FIXME (with the labels for each step)
        self.user_auth_states = {}  # map of user to authentication status ["authenticated", "unauthenticated"]

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
                json_data = json.loads(recv_data.decode('utf-8'))
                print(json_data)
                response = json.dumps(self.delegate_request(c_socket, json_data)).encode('utf-8')
                c_data.outb += response

    # What is the query asking? Respond accordingly and tell the user if the action is
    # successful or not.
    def delegate_request(self, c_socket, json_request):
        src_usr = json_request['source']
        # print(f"Received request '{json_request['action']}' from '{src_usr}'")
        if json_request['type'] == 'SIGN-IN':
            if src_usr in self.user_socks:
                self.send_json(src_usr, 'OK', 'Already signed in')
            else:
                self.user_socks[src_usr] = c_socket
                self.user_auth_states[src_usr] = 'init-auth-req'
                response = {'status': 'hello', 'message': 'world'}
                c_socket.send(json.dumps(response).encode('utf-8'))
                # self.sign_in(c_socket, json_request)
        else:
            # ERROR if client tries to do an action before signing in
            if src_usr not in self.user_socks:
                c_socket.send_json(json.dumps({'status': 'ERROR', 'message': 'Must first sign in with username'})
                                   .encode('utf-8'))
            else:
                if json_request['action'] == 'LIST':
                    self.send_json(src_usr, 'OK', 'Signed In Users: ' + ', '.join(self.users))
                elif json_request['action'] == 'MESSAGE':
                    self.message(src_usr, json_request['dst_usr'], json_request['message'])
                else:
                    print("CLIENT ERROR: Unrecognized action from user " + src_usr)
                    self.send_json(src_usr, 'ERROR', 'Unsupported action')

    # Sends the given message to the destination user, if such a user has signed on already.
    def message(self, src_usr, dst_usr, c_message):
        if dst_usr not in self.user_socks:
            self.send_json(src_usr, 'ERROR', "Target user has not connected to the server")
        else:
            print(f"Sending message from {src_usr} to {dst_usr}")
            src_sock_info = self.user_socks[src_usr].getpeername()
            s_message = f"<From {src_sock_info[0]}:{src_sock_info[1]}:{src_usr}>: {c_message}"
            self.send_json(dst_usr, 'OK', s_message)
            if src_usr != dst_usr:
                self.send_json(src_usr, 'OK', 'Message sent')

    # Helps format JSON responses to clients.
    def send_json(self, dst_usr, status, message):
        json_msg = {'status': status, 'message': message}
        if dst_usr not in self.user_socks:
            print('ERROR: Tried to send message to unrecognized user')
        else:
            self.user_socks[dst_usr].send_json(json.dumps(json_msg).encode('utf-8'))

    # Function to handle LIST command
    def list_command(self, client_addr, clients):
        online_users = list(clients.keys())
        message_to_send = f"Signed In Users: {', '.join(online_users)}"
        response = {'type': 'LIST', 'content': message_to_send}

        self.server_sock.sendto(json.dumps(response).encode(), client_addr)


if __name__ == "__main__":
    with open('config.json') as f:
        server_info = json.load(f)

    kdc = KDC(server_info["KDC_HOST"], server_info["KDC_PORT"])
    kdc.run_server()
