# python_piggyback
Use the ARP protocol to send messages across a censored network using python

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