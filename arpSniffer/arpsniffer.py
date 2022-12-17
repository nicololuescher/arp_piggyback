import socket
import time
import zlib
import hashlib
import nacl.secret
import nacl.utils
import click
import arpsniffer_dbus

# click options
@click.command()
@click.option(
    "--verbose", is_flag=True, default=False, help="show additional information."
)
@click.option(
    "--insert_into_vula",
    is_flag=True,
    default=False,
    help="Automatically insert into vula.",
)
@click.option(
    "--max_age",
    default=10,
    type=int,
    help="Maximum amount of seconds in between each packet.",
)
@click.option(
    "--arp_code", default=0x0806, type=int, help="EtherType to be used in header"
)
@click.option(
    "--packet_max_length", default=60, type=int, help="Max length of packet to capture"
)

# TODO: add doctests, check output for given input
# TODO: integrate dbus and constants into arpsniffer.py
# TODO: rename for vula directory. somthing like layer2sender
def main(verbose, insert_into_vula, max_age, arp_code, packet_max_length):
    verbose
    if verbose:
        print("start capturing...")
    rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(arp_code))

    capture(rawSocket, insert_into_vula, verbose, max_age, packet_max_length)


def capture(raw_socket, insert_into_vula, verbose, max_age, packet_max_length):
    peers = dict()
    # future TODO: look into yeild
    while True:
        packet = raw_socket.recvfrom(packet_max_length)
        src_mac = packet[0][22:28]
        candidate = packet[0][42:]

        if not src_mac in peers:
            peers[src_mac] = {"byte_stream": b"", "updated": 0}

        if candidate[0] != 0:
            now = int(time.time())
            if now - peers[src_mac]["updated"] > max_age:
                if verbose:
                    print("New packet stream detected, clearing data")
                peers[src_mac]["byte_stream"] = b""

            peers[src_mac]["updated"] = int(time.time())
            if verbose:
                print("Received packet")
            peers[src_mac]["byte_stream"] += candidate
            decrypted = decrypt(peers[src_mac]["byte_stream"], src_mac)
            if decrypted is not None:
                if insert_into_vula:
                    arpsniffer_dbus.pydbusProcessDescriptorString(decrypted)
                else:
                    print(decrypted + "\n")
                peers[src_mac]["byte_stream"] = b""


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


if __name__ == "__main__":
    main()
