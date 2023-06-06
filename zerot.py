import sys
from stix2 import *
import json

def packet_list(read_file):
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

  return packets

def create_bundle(packets):
  bundle = Bundle()
  print(bundle)
  print(type(bundle))

  bundle = dict(bundle)
  print(type(bundle))
  objects = list()

  for key in packets:
    src = IPv6Address(value= packets[key]["src"])
    objects.append(json.loads(src.serialize()))

    dst = IPv6Address(value= packets[key]["dst"])
    objects.append(json.loads(dst.serialize()))


    nt = NetworkTraffic(protocols = packets[key]["prot"], src_ref = src.id, dst_ref = dst.id)
    objects.append(json.loads(nt.serialize()))


    src_rel = Relationship(relationship_type='related',
                            source_ref=nt.id,
                            target_ref=src.id)
    objects.append(json.loads(src_rel.serialize()))


    dst_rel = Relationship(relationship_type='related',
                            source_ref=nt.id,
                            target_ref=dst.id)
    objects.append(json.loads(dst_rel.serialize()))

  print(len(objects))
  bundle["objects"] = objects
  print(type(bundle))

  with open("./test.json", "w") as w_file:
    json.dump(bundle, w_file, indent=4)




if __name__ == "__main__":
  packets = packet_list(sys.argv[1])
  create_bundle(packets)


'''
indicator = Indicator(name="File hash for malware variant",
                      pattern="[file:hashes.md5 = 'd41d8cd98f00b204e9800998ecf8427e']",
                      pattern_type="stix")

malware = Malware(name="Poison Ivy",
                  is_family=False)

relationship = Relationship(relationship_type='indicates',
                            source_ref=indicator.id,
                            target_ref=malware.id)

coa = CourseOfAction(name="Write better code",
                     description="The developer who wrote this needs to fix it, or better yet, travel back in time and stop her y>
 

relarelationship = Relationship(relationship_type='indicates',
                            source_ref=indicator.id,
                            target_ref=malware.id)

#OR for better readibility we can declare a relationship in a more natural source --> target way.

#relationship = Relationship(indicator, 'indicates', malware)

bundle = Bundle(indicator, malware, coa, relationship, relationship1)

#print(indicator.serialize(pretty=True))
#print(malware.serialize(pretty=True))
#print(relationship.serialize(pretty=True))

print(bundle.serialize(pretty=True))

'''
