import csv
import fcntl
import math
import random
import socket
import struct
import time
import zlib
import hashlib
import nacl.secret
import nacl.utils
import click
import arpSender_dbus
import json

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
@click.option("--descriptor", required=False, type=str, help="descriptor to use for sending packets.")
@click.option(
    "--verbose", is_flag=True, default=False, help="show additional information."
)
@click.option(
    "--is_reply",
    is_flag=True,
    default=False,
    help="Send reply packets instead of request.",
)
def main(interface, descriptor, verbose, is_reply):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)  # open raw socket
    s.bind((interface, 0))  # bind to interface

    # get dynamic information
    src_mac = get_mac(s, interface)
    ip = get_ip(interface)
    dest_ip = get_arp(verbose)
    op_code = get_op_code(is_reply, verbose)

    if descriptor == None:
        descriptors = json.loads(arpSender_dbus.pydbusGetLatestDescriptor())
        descriptor = build_vula_descriptor(descriptors.get(socket.inet_ntoa(ip)))
        if verbose:
            print("Got descriptor", descriptor)

    message = compress_and_encrypt(
        descriptor, src_mac, verbose
    )  # compress and encrypt message
    packet_header = generate_header(
        src_mac, op_code, ip, dest_ip
    )  # generate packet header
    send_packet(s, packet_header, message, verbose)  # send arp packet


def build_vula_descriptor(input):
    output = ""
    output += "addrs=" + input["addrs"] + "; "
    output += "c=" + input["c"] + "; "
    output += "dt=" + input["dt"] + "; "
    if input["e"] == "False":        
        output += "e=0; "
    else:
        output += "e=1; "
    output += "hostname=" + input["hostname"] + "; "
    output += "pk=" + input["pk"] + "; "
    output += "port=" + input["port"] + "; "
    output += "r=" + input["r"] + "; "
    output += "s=" + input["s"] + "; "
    output += "vf=" + input["vf"] + "; "
    output += "vk=" + input["vk"] + ";"
    return output

def send_packet(socket, packet_header, packet_payload, verbose):
    # segment packet into 17 bit chunks for a total packet length of 60, icluding 1 enumerator byte
    for i in range(math.ceil(len(packet_payload) / (60 - len(packet_header) - 1))):
        packet = (
            packet_header
            + i.to_bytes(1, "big")  # add enumerator
            + packet_payload[
                i
                * ((60 - len(packet_header) - 1)) : (
                    i + 1
                )  # add corresponding packet chunk
                * ((60 - len(packet_header) - 1))
            ]
        )
        # send packet
        if verbose:
            print(
                "Sending packet",
                i + 1,
                "of",
                math.ceil(len(packet_payload) / (60 - len(packet_header) - 1)),
            )
        time.sleep(random.uniform(0.01, 0.1))
        socket.send(packet)


def get_op_code(is_reply=False, verbose=False):
    # set op code, 0x01 for request and 0x02 for reply
    if verbose:
        print("Sending packet as reply." if is_reply else "Sending packet as request.")
    if is_reply:
        return b"\x00\x02"
    else:
        return b"\x00\x01"


def get_ip(interface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_aton(
        socket.inet_ntoa(
            fcntl.ioctl(
                s.fileno(), 0x8915, struct.pack("256s", interface[:15].encode("utf-8"))
            )[20:24]
        )
    )


def get_mac(socket, interface):
    return fcntl.ioctl(
        socket.fileno(), 0x8927, struct.pack("256s", bytes(interface[:15], "utf-8"))
    )[18:24]


def compress_and_encrypt(msg, encryption_key, verbose=True):
    message = (
        str(int(time.time())) + msg
    )  # add unix timestamp to message to add some randomness to encrypted text
    hd = bytes(message, "utf-8")  # encode message into bytes
    hdc = zlib.compress(hd)  # compress with zlib
    key = hashlib.sha256(encryption_key).digest()  # generate key from source mac
    box = nacl.secret.SecretBox(key)  # generate enryptor
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)  # add default nonce
    if verbose:
        print("message length before compression:", len(hd))
        print("message length after compression:", len(hdc))
    return box.encrypt(hdc, nonce)  # return encryped text


def generate_header(src_mac, op_code, ip, dest_ip):
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
    packet_header += ip  # sender ip
    packet_header += zero_mac  # destination mac
    packet_header += dest_ip  # destination ip

    return packet_header


def get_arp(verbose=False):
    with open("/proc/net/arp") as arp_table:  # read arp cache
        reader = list(
            csv.reader(arp_table, skipinitialspace=True, delimiter=" ")
        )  # generate csv reader
    dest_ip = b""
    arp_cache = [a[0] for a in reader[1:]]  # skip header line and read ip field
    if len(arp_cache) == 0:
        dest_ip = (
            get_ip()[0:3] + b"\x01"
        )  # if chache is empty, take 0x01 address of own ip
    else:
        random_ip = random.choice(arp_cache)  # pick random ip
        dest_ip = socket.inet_aton(random_ip)

    if verbose:
        print("Setting random arp ip as destination.")
        print("Arp cache:", arp_cache)
        print("Chosen Destination ip:", random_ip)

    return dest_ip


if __name__ == "__main__":
    main()
