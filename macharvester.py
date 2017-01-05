import sys
import re
from scapy.all import *

# Open MAC address Database. Format: xxxxxx <Vendor>
with open('mac_vendors.txt','r') as vendor_file:
    vendor_lines = [vendor.rstrip() for vendor in vendor_file]

# Currently overwrites log each run
f = open('harvest.log', 'wb+')

found_macs = []

def vendor_lookup(mac):
	vendor_mac=re.compile(re.sub(':','',mac)[0:6],re.IGNORECASE)
	for vendor in vendor_lines:
		if re.search(vendor_mac,vendor):
			return vendor[7:]

def PacketHandler(pkt):
	if pkt.addr2 != None and pkt.addr2 not in found_macs:
        vendor = vendor_lookup(pkt.addr2)
		found_macs.append(pkt.addr2)
		f.write("%s,%s\n" % (pkt.addr2, vendor))
		f.flush()
		os.fsync(f.fileno())

if len(sys.argv) == 2:
	sniff(iface=sys.argv[1], prn = PacketHandler)
else:
    print "Usage: %s <Interface>"%(sys.argv[0])
