import sys
import re
import collections
import thread

from scapy.all import *
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from matplotlib import style

# Open MAC address Database. Format: xxxxxx <Vendor>
with open('mac_vendors.txt','r') as vendor_file:
    vendor_lines = [vendor.rstrip() for vendor in vendor_file]

# Currently overwrites log each run
f = open('harvest.log', 'wb+')

found_macs = []
found_vendors = []

style.use('fivethirtyeight')
fig = plt.figure()
ax1 = fig.add_subplot(1,1,1)

def remove_value_from_list(haystack, needle):
   return [value for value in haystack if value != needle]

def update_pie_chart(i):
    # Get Ordered Dictionary of (Vendors, Occurances) sorted by Number of Appearances
    vendors_list = remove_value_from_list(found_vendors,None)
    vendors_count = collections.Counter(vendors_list)
    vendors_sorted = sorted(vendors_count.items(), key=lambda x: x[1])
    vendors = collections.OrderedDict(vendors_sorted)
    #Clear and redraw pie chart
    ax1.clear()
    plt.title('MAC Addresses by Vendor')
    ax1.pie(
		vendors.values(),
		labels=vendors.keys(),
		autopct='%1.1f%%',
		shadow=True,
		startangle=180)

def vendor_lookup(mac):
	vendor_mac=re.compile(re.sub(':','',mac)[0:6],re.IGNORECASE)
	for vendor in vendor_lines:
		if re.search(vendor_mac,vendor):
			return vendor[7:]

def PacketHandler(pkt):
	if pkt.addr2 != None and pkt.addr2 not in found_macs:
        vendor = vendor_lookup(pkt.addr2)
		found_macs.append(pkt.addr2)
		found_vendors.append(vendor)
		f.write("%s,%s\n" % (pkt.addr2, vendor))
		f.flush()
		os.fsync(f.fileno())

if len(sys.argv) == 2:
    # Start Packet Sniffer in separate thread
	thread.start_new_thread(sniff, (), dict(iface=sys.argv[1], prn=PacketHandler))
    # Setup Pie Chart, Begin 1s refresh, and show initial graph
	update_pie_chart(0)
	ani = animation.FuncAnimation(fig, update_pie_chart, interval=1000)
	plt.show()
else:
    print "Usage: %s <Interface>"%(sys.argv[0])
