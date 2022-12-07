from multiprocessing import Process
from re import S
import socket
import time
import zlib
import hashlib
import nacl.secret
import nacl.utils
import click
from yaml import safe_dump

updated = 0
peers = dict()
is_verbose = False

# click options
@click.command()
@click.option(
    "--verbose", is_flag=True, default=False, help="show additional information."
)
def main(verbose):
    global updated, peers, is_verbose
    is_verbose = verbose
    if is_verbose:
        print("start capturing...")
    rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))

    updated = int(time.time())

    process = Process(target=buffer_timer)
    process.start()

    capture(rawSocket, process)


def capture(raw_socket, process):
    global peers, updated, is_verbose
    peers = dict()
    peerPositions = dict()
    while True:
        packet = raw_socket.recvfrom(2048)
        src_mac = packet[0][22:28]
        candidate = packet[0][42:]

        if not src_mac in peers:
            peers[src_mac] = b""

        if not src_mac in peerPositions:
            peerPositions[src_mac] = 0

        if candidate[0] == 0 and candidate[1] != 0 and peerPositions[src_mac] != 0:
            peerPositions[src_mac] = 0
            peers[src_mac] = b""

        if candidate[0] == peerPositions[src_mac] and candidate[1] != 0:
            updated = int(time.time())
            if len(peers[src_mac]) > 1000:
                del peers[src_mac]
            if is_verbose:
                print("Received packet number", peerPositions[src_mac])
            peers[src_mac] += candidate[1:]
            peerPositions[src_mac] += 1
            decrypted = decrypt(peers[src_mac], src_mac)
            if decrypted is not None:
                process.terminate()
                print(decrypted)
                break


def decrypt(message, key):
    try:
        key = hashlib.sha256(key).digest()
        box = nacl.secret.SecretBox(key)
        decrypt = box.decrypt(message.strip(b"\x00"))
        decrypt = zlib.decompress(decrypt)
        if decrypt[10:15] == b"addrs":
            return str(decrypt[10:], "utf-8")
        else:
            return None
    except:
        return None


def buffer_timer():
    global updated, peers, is_verbose
    while True:
        if int(time.time()) - updated > 90:
            print(peers)
            updated = int(time.time())
            peers = dict()
            if is_verbose:
                print("Buffer cleared!")
        time.sleep(1)


if __name__ == "__main__":
    main()
