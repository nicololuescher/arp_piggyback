import fcntl
import math
import os
import random
import socket
import struct
import time
import zlib
import hashlib
import nacl.secret
import nacl.utils
import click
from subprocess import check_output

# static values
broadcast_mac = b"\xff\xff\xff\xff\xff\xff"
ethernet_type = b"\x08\x06"
hardware_type = b"\x00\x01"
protocol_type = b"\x08\x00"
hardware_size = b"\x06"
protocol_size = b"\x04"
zero_mac = b"\x00\x00\x00\x00\x00\x00"

# click options
@click.command()
@click.option("--interface", type=str, help="interface to use for sending packets.")
@click.option("--descriptor", type=str, help="descriptor to use for sending packets.")
@click.option("--verbose", is_flag=True, default=False, help="show additional information.")
@click.option("--is_reply", is_flag=True, default=False, help="Send reply packets instead of request.")
def main(interface, descriptor, verbose, is_reply):
    arp_cache = []

    for device in os.popen('arp -a'):
        _, ip, _, _, iface = device.split(maxsplit=4)
        if interface in iface:
            arp_cache.append(ip[1:len(ip) -1])


    # open raw socket
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((interface, 0))

    # get dynamic information
    src_mac = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s',  bytes(interface[:15], 'utf-8')))[18:24]
    ip = socket.inet_aton(
        check_output(
            "ip -4 addr show " + interface + " | grep -oP '(?<=inet\s)\d+(\.\d+){3}'",
            shell=True,
        ).decode("utf-8")
    )
    print(arp_cache)
    
    if len(arp_cache) == 0:
        dest_ip = ip[0:3] + b'\x01'
    else:
        dest_ip = socket.inet_aton(random.choice(arp_cache))

    if is_reply:
        op_code = b'\x00\x02'
    else:
        op_code = b'\x00\x01'

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
    packet_header = broadcast_mac  # broadcast mac
    packet_header += src_mac  # source mac
    packet_header += ethernet_type  # ethernet type
    packet_header += hardware_type  # hardware type
    packet_header += protocol_type  # protocol type
    packet_header += hardware_size  # hardware size
    packet_header += protocol_size  # protocol size
    packet_header += op_code  # opcode
    packet_header += src_mac  # sender mac
    packet_header += ip # sender ip
    packet_header += zero_mac  # destination mac
    packet_header += dest_ip  # destination ip

    # append message
    for i in range(math.ceil(len(encrypt) / (60 - len(packet_header) - 2))):
        packet = packet_header + i.to_bytes(1, 'big') + b'\x64' + encrypt[i * ((60 - len(packet_header) - 2)): (i + 1) * ((60 - len(packet_header) - 2))]

        # send packet
        time.sleep(random.uniform(0.01, 0.1))
        s.send(packet)

if __name__ == "__main__":
    main()
