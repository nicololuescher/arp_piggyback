import socket
import zlib
import hashlib
import nacl.secret
import nacl.utils
import click
from uuid import getnode
from subprocess import check_output

# static values
broadcast_mac = b"\xff\xff\xff\xff\xff\xff"
ethernet_type = b"\x08\x06"
hardware_type = b"\x00\x01"
protocol_type = b"\x08\x00"
hardware_size = b"\x06"
protocol_size = b"\x04"
op_code = b"\x00\x01"
zero_mac = b"\x00\x00\x00\x00\x00\x00"

# click options
@click.command()
@click.option("--interface", type=str, help="interface to use for sending packets.")
@click.option("--descriptor", type=str, help="descriptor to use for sending packets.")
@click.option("--verbose", is_flag=True, default=False, help="show additional information.")
def main(interface, descriptor, verbose):
    # open raw socket
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((interface, 0))

    # get dynamic information
    src_mac = getnode().to_bytes(6, "big")
    ip = socket.inet_aton(
        check_output(
            "ip -4 addr show " + interface + " | grep -oP '(?<=inet\s)\d+(\.\d+){3}'",
            shell=True,
        ).decode("utf-8")
    )

    # compress and encrypt descriptor
    hd = bytes(descriptor, "utf-8")
    hdc = zlib.compress(hd)
    key = hashlib.sha256(src_mac).digest()
    box = nacl.secret.SecretBox(key)
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    encrypt = box.encrypt(hdc, nonce)

    if verbose:
        print("message length before compression:", len(hd))
        print("message length after compression:", len(hdc))

    # build arp packet
    packet = broadcast_mac  # broadcast mac
    packet += src_mac  # source mac
    packet += ethernet_type  # ethernet type
    packet += hardware_type  # hardware type
    packet += protocol_type  # protocol type
    packet += hardware_size  # hardware size
    packet += protocol_size  # protocol size
    packet += op_code  # opcode
    packet += src_mac  # sender mac
    packet += ip # sender ip
    packet += zero_mac  # destination mac
    packet += ip  # destination ip

    # append message
    packet += encrypt

    # send packet
    s.send(packet)

if __name__ == "__main__":
    main()
