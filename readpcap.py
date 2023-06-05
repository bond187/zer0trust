from kamene.all import *

def readpcap(file):
  with PcapReader(file) as pcap:
    for pkt in pcap:
      print(pkt)
      print("")
  return 0

if __name__ == "__main__":
  readpcap("Zer0Trust-5G.pcap-01.cap")
  print("Done, bye!")
