import pandas as pd
import pyshark
import sys
import csv

# Obtain the data: Timestamp,SourceIP,SourcePort,DestinationIP,DestinationPort,Protocol,DDOS?
#Calculate Mean Packets Per Second per
cap = pyshark.FileCapture('test1.pcap')
for packet in cap:
	print("Datetime")
	print(packet.sniff_time)
	print("Protocol:")
	if 'IP' in packet:
		try:
			print(packet.ip.proto)
		except:
			print("Info Not Found")
		print("SourceIP")
		try:
			print(packet.ip.src)
		except:
			print("Info Not Found")
	elif 'IPV6' in packet:
		try:
			print(packet.ipv6.nxt)
		except:
			print("Info Not Found")
		print("SourceIP")
		try:
			print(packet.ipv6.src)
		except:
			print("Info Not Found")
	else:
		pass
	print("")
print("Time passed")
print(len(cap))
print((cap[47].sniff_time-cap[0].sniff_time).total_seconds())
#print((cap[-1].sniff_time))
#print((cap[-1].sniff_time)-(cap[0].sniff_time))