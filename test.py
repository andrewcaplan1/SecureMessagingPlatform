import subprocess
from client import Client
from kdc import KDC

LOCAL_HOST = '127.0.0.1'
KDC_PORT = 55000
ALICE_PORT = 55001
BOB_PORT = 55002


def test_simple():
    kdc = KDC(LOCAL_HOST, KDC_PORT)
    # alice = Client(LOCAL_HOST, ALICE_PORT, LOCAL_HOST, KDC_PORT,
    #                'alice', 'supersecurepassword')
    # bob = Client(LOCAL_HOST, BOB_PORT, LOCAL_HOST, KDC_PORT,
    #              'bob', 'bobisthebest')

    k_result = subprocess.run(['python3', 'kdc.py'], capture_output=True, text=True)
    k_result.run()

    a_result = subprocess.Popen(['python3', 'client.py'], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
    a_result.communicate('')
    print("HELLOOO")
    print(k_result.stdout)
