# python_piggyback
Use the ARP protocol to send encrypted messages in the trailer of an ARP packet.
This encryption is used to smuggle a Vula descriptor to other Vula users running arp_piggyback on the same network segment.

## Security
The common sizes of ARP broadcast packets are between 42 (request) and 60
(reply) bytes. The structure of the packet is such that a request and a reply
usually have around 18 bytes of zero padding, if they are padded at all. It is
possible to use those 18 bytes as a covert channel by filling them with random
looking data.

This encryption is not meant to forward-secret, it's simply to randomize the
payload and defeat a trivial packet sniffers. The key is currently derived from
a hash of the sender's MAC address. The payload is encrypted using an NaCL Box
with a random nonce value. The length of the packet is much larger than the
common 60 byte payload. Currently this means it is trivial to discover this
protocol simply by counting packet lengths and performing trial decryption.

The decryption process also decompresses the payload and it likely possible to
exploit the decompression code.

## Future work
The sender will generate a compressed, encrypted payload and break it into n
messages. The 18 byte padding which is normally zero will be the space where
each chunk of the encrypted payload will be stored for sending.

The receiver will sniff and build a payload in memory until the full payload is
received for each MAC:IP pair. Each packet may trigger a trial decryption, and
if it successfully decrypts, we know that we have discovered another
arp_piggyback sender. We will then feed the descriptor into Vula.

The sender and receiver will listen forever, sending and receiving peers as
needed.

## Get Vula descriptor and send it
```
vula verify my-descriptor| sudo python3 arpSender.py --interface wlp82s0 --descriptor -
```


## remove arp peer and add it dynamically
```bash
vula peer remove {id}
sudo python3 arpsniffer.py --insert_into_vula | vula peer import
vula peer
```

## get your descriptor
```bash
vula verify my-descriptor
```

## send descriptor via arp
```bash
sudo python3 arpSender.py --interface ens33 --descriptor '{myDescriptor}' --verbose
```