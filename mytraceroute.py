import argparse
from ipwhois import IPWhois
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr1
import IPy
#from pprint import pprint as pp

def mytraceroute(destination):
	for i in range(1,31):
		pkt = IP(dst=destination, ttl=i) / UDP(dport=33434)
		reply = sr1(pkt, verbose=0, timeout=10)
		if reply is not None:
			ip_addr = reply.src
			if IPy.IP(ip_addr).iptype() != "PRIVATE":
				obj = IPWhois(ip_addr)
				results = obj.lookup()
				#pp(results)
				if results.get('nets', None):
					print(ip_addr, ' : ', results.get('asn', '_'), '/', results['nets'][0].get('name', '_'), 
						'/', results.get('asn_country_code', '_'), '/', results['nets'][0].get('description', '_'))
				else:
					print(ip_addr, ' : ', results.get('asn', '_'), '/', results.get('asn_country_code', '_'))
			else: 
				print(ip_addr)
			if reply.type == 3: 
				print("Destination reached")
				break
		else:
			print("***")


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Perfom a personalized traceroute')
	parser.add_argument('-d', '--destination', help='destination domain')
	args = parser.parse_args()
	mytraceroute(args.destination)