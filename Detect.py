from scapy.all import *
import re
import urllib2

reasonList = []
urlList = []
badWordList = []

def badWords():
        try:
                f = open("word", 'r')

                while True:
                        word = f.readline()
                        if not word:
                                break

                        badWordList.append(word)

                f.close()

        except IOError:
                print "IO Error"


def detectBadSite(data):
        global reasonList
        reasonList = []
        limitCount = 0

        for word in badWordList:

                if bool(re.search(word, data)):
                        reasonList.append(word)
                        limitCount += 1

                        if limitCount > 1:
                                return True

        return False

def webParser(url):
        try:
                handle = urllib2.urlopen(url)
                data = handle.read()

                if detectBadSite(data):
                        try:
                                f = open("badSite", 'a')
                                f.write("URL : " + url+"\r\n")

                                for reason in reasonList:
                                        f.write("\t- "+ reason)

                                f.write("\r\n\r\n")
                        except IOError:
                                print "IO Error"


        except urllib2.HTTPError, e:
                print "HTTP Error"

        except urllib2.URLError, e:
                print "URL Error"

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

if __name__=="__main__":

        badWords()

        sniff(prn = visitUrl, lfilter= lambda p: "GET" in str(p), filter = "tcp port 80")
