from scapy.all import *
from BeautifulSoup import *
import re
import urllib2


urlList = []

	
def webParser(url):
	handle = urllib2.urlopen(url)
	data = handle.read()
	print "================"
	print url
	print data
	print "============="
	
def visitUrl(pkt):
	packet = str(pkt)
	if packet.find('GET'):
		data = "\n".join(pkt.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n"))
		data = re.search("Referer: .+", data)
		if (bool(data)):
			data = re.search("http.+", data.group(0))
			url = data.group(0)
			if urlList.count(url) < 1:
				webParser(url)
			urlList.append(url)

sniff(prn = visitUrl, lfilter= lambda p: "GET" in str(p), filter = "tcp port 80")

