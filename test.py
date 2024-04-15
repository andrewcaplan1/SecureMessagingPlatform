import subprocess
import time

from client import Client
from kdc import KDC

LOCAL_HOST = '127.0.0.1'
KDC_PORT = 55000
ALICE_PORT = 55001
BOB_PORT = 55002


def create_process(executable_path):
    """ Helper function to create a subprocess for a given executable. """
    return subprocess.Popen(
        executable_path,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )


def test_processes():
    # Create subprocesses for A, B, and C
    process_k = create_process('./kdc.py')
    process_a = create_process('./client.py')
    process_b = create_process('./client.py')

    try:
        # Andrew logs in
        process_a.stdin.write("Andrew\n")
        process_a.stdin.flush()
        process_a.stdin.write("HardPassword123\n")
        process_a.stdin.flush()
        time.sleep(1)  # logging in might have a delay

        # test that only Andrew is online
        process_a.stdin.write("LIST\n")
        process_a.stdin.flush()
        list1 = process_a.stdout.readline().strip()
        assert list1 == "Andrew"

        # Amanda logs in
        process_b.stdin.write("Amanda\n")
        process_b.stdin.flush()
        process_b.stdin.write("PasswordHard321\n")
        process_b.stdin.flush()
        time.sleep(1)  # logging in might have a delay

        # test that both Amanda and Andrew are online
        process_b.stdin.write("LIST\n")
        process_b.stdin.flush()
        list2 = process_b.stdout.readline().strip()
        assert list2 == "Andrew, Amanda"

        # test that Andrew can send one message to Amanda
        process_a.stdin.write("MESSAGE Amanda Hi Amanda, how are you?\n")
        process_a.stdin.flush()
        message1 = process_b.stdout.readline().strip()
        assert message1 == 'Hi Amanda, how are you?'

        # test that Amanda can send two consecutive messages to Andrew
        process_b.stdin.write("MESSAGE Andrew Hi Andrew, I'm pretty good.\n")
        process_b.stdin.flush()
        message2 = process_a.stdout.readline().strip()
        assert message2 == "Hi Andrew, I'm pretty good."
        process_b.stdin.write("MESSAGE Andrew How about you??\n")
        process_b.stdin.flush()
        message3 = process_a.stdout.readline().strip()
        assert message3 == 'How about you??'
    finally:
        # Clean up
        process_k.terminate()
        process_a.terminate()
        process_b.terminate()
        process_k.wait()
        process_a.wait()
        process_b.wait()


if __name__ == "__main__":
    test_processes()
