from multiprocessing import Process
import socket
import time
import zlib
import hashlib
import nacl.secret
import nacl.utils
import click

update = 0
peers = dict()

# click options
@click.command()
@click.option("--verbose", is_flag=True, default=False, help="show additional information.")
def main(verbose):
    global updated, peers, is_verbose
    is_verbose = verbose
    if is_verbose:
        print("start capturing...")
    rawSocket= socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))

    current_position = 0
    updated = int(time.time())
    peers = dict()

    process = Process(target=buffer_timer)
    process.start()

    while True:

        packet = rawSocket.recvfrom(2048)
        src_mac = packet[0][22:28]
        candidate = packet[0][42:]

        if not src_mac in peers:
            peers[src_mac] = b''

        if candidate[0] == current_position and candidate[1] == 100:
            updated = int(time.time())
            if len(peers[src_mac]) > 1000:
                del(peers[src_mac])
            if is_verbose:
                print("Received packet number ", current_position)
            peers[src_mac] += candidate[2:]
            current_position += 1
            try:
                key = hashlib.sha256(src_mac).digest()
                box = nacl.secret.SecretBox(key)
                decrypt = box.decrypt(peers[src_mac].strip(b'\x00'))
                decrypt = zlib.decompress(decrypt)
                if(decrypt[10:15] == b'addrs'):
                    descriptor = str(decrypt[10:], "utf-8")
                    print(descriptor + "\n")
                    process.terminate()
                    break
            except:
                pass


# XXX this doesn't work
def buffer_timer():
    global updated, peers
    while True:
        if(int(time.time()) - updated > 90):
            print(peers)
            updated = int(time.time())
            peers = dict()
            if is_verbose:
                print("Buffer cleared!")


if __name__ == "__main__":
    main()