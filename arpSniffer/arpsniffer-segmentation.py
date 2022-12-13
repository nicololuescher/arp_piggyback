from multiprocessing import current_process
import os
import socket
import subprocess
import zlib
import hashlib
import nacl.secret
import nacl.utils
import click
import pydbus
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
def main(verbose, insert_into_vula):
    if verbose:
        print("start capturing...")
    rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))

    packet_stream = b""
    current_position = 0

    while True:
        packet = rawSocket.recvfrom(2048)
        src_mac = packet[0][22:28]
        candidate = packet[0][42:]

        if candidate[0] == current_position and candidate[1] != 0:
            print("test")
            if verbose:
                print("Received packet number ", current_position)
            packet_stream += candidate[2:]
            current_position += 1
            try:
                key = hashlib.sha256(src_mac).digest()
                box = nacl.secret.SecretBox(key)
                decrypt = box.decrypt(packet_stream.strip(b"\x00"))
                decrypt = zlib.decompress(decrypt)
                if decrypt[0:5] == b"addrs":
                    descriptor = str(decrypt, "utf-8")
                    if insert_into_vula:
                       arpsniffer_dbus.pydbusProcessDescriptorString(descriptor)
                    else:
                        print(descriptor + "\n")
                    break
            except:
                pass


if __name__ == "__main__":
    main()
