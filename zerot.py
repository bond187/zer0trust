import sys
import os
from stix2 import *
import json

def packet_list(read_file):
'''
packet_list() takes a file as an argument, and assuming that file is a csv holding pcap date (as exported by wireshark), and 
outputs a dictionary of dictionaries. Each inner item corresponds to a packet in the packet capture, and the time, src, dst, 
protocol, len, and info fields are identified and serve as keys for each packet item. In addition, to reduce massive duplication,
lists of unique source ips and destination ips are returned. That way, when stix objects are being created later on, there will
be network traffic for each packet, and one source ip and destination ip, which have relationships to many network traffic objects.
'''
  with open(read_file, 'r') as file:
    packets = dict()
    for i, line in enumerate(file.readlines(),0):
      if i > 0:
        print(i)
        words = line.split(",")
        pkt = dict()
        pkt["time"] = words[1].strip('\"')
        pkt["src"] = words[2].strip('\"')
        pkt["dst"] = words[3].strip('\"')
        pkt["prot"] = words[4].strip('\"')
        pkt["len"] = words[5].strip('\"')
        pkt["info"] = words[6].strip('\"')

        packets[str(words[0])] = pkt

    unique_srcs = list()
    unique_dsts = list()
    for pkt in packets:
      if packets[pkt]["src"] not in unique_srcs:
        unique_srcs.append(packets[pkt]["src"])
      if packets[pkt]["dst"] not in unique_dsts:
        unique_dsts.append(packets[pkt]["dst"])

  print(len(unique_srcs), len(unique_dsts))
  return packets, unique_srcs, unique_dsts

def create_bundle(packets, un_srcs, un_dsts, file):
'''
create_bundle does what it says on the tin, it takes the dict of dicts object packets, unique sources and destination ip lists,
and the name of the input file (to intelligently name the output file). It iterates over the packet info provided and makes
a stix bundle of network traffic objects, ipv6 objects, and relationshipd between them. The 2G sample file ends up with 36k 
objects, way too big for my stig to render, but the 5G file has only 1528, which is more managable.
'''
  bundle = Bundle()
  print(bundle)
  print(type(bundle))

  bundle = dict(bundle)
  print(type(bundle))
  objects = list()

  src_ids = dict()
  dst_ids = dict()

  for src in un_srcs:
    new_src = IPv6Address(value= src)
    objects.append(json.loads(new_src.serialize()))
    src_ids[src] = new_src.id

  for dst in un_dsts:
    new_dst = IPv6Address(value= dst)
    objects.append(json.loads(new_dst.serialize()))
    dst_ids[dst] = new_dst.id

  for key in packets:
    nt = NetworkTraffic(protocols = packets[key]["prot"], src_ref = src_ids[packets[key]["src"]], dst_ref = dst_ids[packets[key]["dst"]])
    objects.append(json.loads(nt.serialize()))

    src_rel = Relationship(relationship_type='related',
                            source_ref=nt.id,
                            target_ref=src_ids[packets[key]["src"]])
    objects.append(json.loads(src_rel.serialize()))


    dst_rel = Relationship(relationship_type='related',
                            source_ref=nt.id,
                            target_ref=dst_ids[packets[key]["dst"]])
    objects.append(json.loads(dst_rel.serialize()))

  print(len(objects))
  bundle["objects"] = objects
  parse(bundle)
  print(type(bundle))

  filename, ext = os.path.splitext(file)

  with open("./{}-out.json".format(filename), "w") as w_file:

    json.dump(bundle, w_file, indent=4)

#-------------------------------------------------------------------------------------

if __name__ == "__main__":
  packets, sources, dests = packet_list(sys.argv[1])
  create_bundle(packets, sources, dests, sys.argv[1])


