from scapy import *

packets = rdpcap("Zer0Trust-5G.pcap-01.cap")
packets.summary()

for packet in packets:
  if packet.hadlayer(UDP):
    print(packet.summary())
