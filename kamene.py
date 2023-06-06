from kamene import *

with PcapReader('Zer0Trust-5G.pcap-01.cap') as pcap_reader:
  for pkt in pcap_reader:
    #do something with the packet
    print(pkt)
