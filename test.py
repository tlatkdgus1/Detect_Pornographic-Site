from scapy.all import *
from urllib import *
from BeautifulSoup import *

#def checkHarmful(dnsName):
		
def webParser(dnsName):
	handle = urlopen("http://"+dnsName)
	



def packet_print(pkt):
	if pkt.haslayer(DNS):
		if pkt.qdcount > 0 and isinstance(pkt.qd, DNSQR):
			dnsName = pkt.qd.qname
		elif pkt.ancount > 0 and isinstance(pkt.an, DNSRR):
			dnsName = pkt.an.rdata
		
		print dnsName[:(len(dnsName)-1)]	
	#	checkHarmful(dnsName)
		webParser(dnsName)

sniff(prn = packet_print)

