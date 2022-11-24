# courtesy of https://stackoverflow.com/users/302831/santa and https://stackoverflow.com/users/3325230/user3325230
import socket
import bz2

rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))

while True:

    packet = rawSocket.recvfrom(2048)

    # candidate = packet[0][42:47]
    candidate = packet[0][42:]
    if(candidate[0:2] != b'\x00\x00'):
        candidate = bz2.decompress(candidate)
        if(candidate[0:5] == b'vula;'):
            descriptor = candidate[5:]
            print(str(descriptor, "utf-8") + "\n")
            break
    