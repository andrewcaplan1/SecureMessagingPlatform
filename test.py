from client import Client
from kdc import KDC

LOCAL_HOST = '127.0.0.1'
KDC_PORT = 55000
ALICE_PORT = 55001
BOB_PORT = 55002


def test_simple():
    kdc = KDC(LOCAL_HOST, KDC_PORT)
    alice = Client(LOCAL_HOST, ALICE_PORT, LOCAL_HOST, KDC_PORT,
                   'alice', 'supersecurepassword')
    bob = Client(LOCAL_HOST, BOB_PORT, LOCAL_HOST, KDC_PORT,
                 'bob', 'bobisthebest')

    kdc.run_server()
    alice_input = ""
    alice.run_client(alice_input)

    bob_input = ""
    bob.run_client(bob_input)



