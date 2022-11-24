# python_piggyback
Use the ARP protocol to send messages across a censored network using python

## get descriptor
`vula verify my-descriptor`

## remove arp peer and add it dynamically
```bash
vula peer remove {id}
sudo python3 arpsniffer.py  | vula peer import
vula peer
```