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

    kdc_thread = threading.Thread(target=kdc.run_server, args=(1,))
    alice_thread = threading.Thread(target=alice.run_server, args=(1,))
    bob_thread = threading.Thread(target=bob.run_server, args=(1,))

    bob.run_client(bob_input)



