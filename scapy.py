import argparse
import os
import sys
from scapy.all import all
from pprint import pprint

logfile = rdpcap('Zer0Trust-5G.pcap-01.cap')
pprint(list(logfile))





'''
def process_pcap(file_name):
  print('Opening {}...'.format(file_name))

  count = 0
  for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
    count += 1

  print('{contains {} packets'.format(file_name, count))

if __name__ == '__main__':
  parser = argparse.ArgumentParser(description='PCAP reader')
  parser.add_argument('--pcap', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)
  args = parser.parse_args()

  file_name = args.pcap
  if not os.path.isfile(file_name):
    print('"{}" does not exist'.format(file_name), file=sys.stderr)
    sys.exit(-1)

  process_pcap(file_name)
  sys.exit(0)
'''
