import socket
import bz2
import hashlib
import nacl.secret
import nacl.utils

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(("ens33", 0))

descriptor = "vula;addrs=192.168.176.128; c=o7IxRod2Zwp9zgJHCGWZEAto28rl1EKAJ75kHL+Ie9a737Az2y782L3BVvregsuQEDXvKFRwKE74ncImWHIXYg==; dt=86400; e=0; hostname=DebianVm1.local.; pk=k7iqQYGfXToQEGgkn9bVeiwd/Ja7wNjuIwba5C0ON1Y=; port=5354; r=; s=hWM6gboPkm2gCOyjUOEbm9dNWvKPS+qyQqr5+cqjpxyeFYznjZKyDfE54MOs+iP6xzUCa57DHiGzDxn01xcWCg==; vf=1669311771; vk=RjNsobCxqVkpIDZJkRKwyrtoitSHWU8tH4my6saexX0=;"

hd = bytes(descriptor, "utf-8")

hdc = bz2.compress(hd, compresslevel=9)

src_mac = b"\x00\x0c\x29\x92\xe0\xcb"

key = hashlib.sha256(src_mac).digest()

box = nacl.secret.SecretBox(key)

nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)

encrypt = box.encrypt(hdc, nonce)

print(len(hd), len(hdc))

packet = b"\xff\xff\xff\xff\xff\xff"  # broadcast mac
packet += src_mac  # source mac
packet += b"\x08\x06"  # hardware size
packet += b"\x00\x01"  # hardware type
packet += b"\x08\x00"  # protocol type
packet += b"\x06"  # hardware size
packet += b"\x04"  # protocol size
packet += b"\x00\x01"  # opcode
packet += b"\x00\x0c\x29\x92\xe0\xcb"  # sender mac
packet += b"\xc0\xa8\xb0\x80"  # sender ip
packet += b"\x00\x00\x00\x00\x00\x00"  # destination mac
packet += b"\xc0\xa8\xb0\x81"  # destination ip
# packet += b'\x48\x65\x6C\x6C\x6F\x20\x41\x70\x70\x53\x65\x63'   # message in padding
# packet += b'\x00\x00\x00\x00\x00\x00'                           # rest of padding, 60 bytes in total

packet += encrypt

s.send(packet)
