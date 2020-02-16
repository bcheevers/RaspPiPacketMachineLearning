import pandas as pd
import numpy as np
import pyshark
import sys
import datetime

# Obtain the data: Timestamp,SourceIP,SourcePort,DestinationIP,DestinationPort,Protocol,DDOS?
#Calculate Mean Packets Per Second per
cap = pyshark.FileCapture('QueensNetworkNormal1.pcap')
counter=1
for packet in cap:
	print("ID"+str(counter))
	print("Time: "+packet.sniff_timestamp)
	
	counter+=1
	if 'ARP' in packet:
		#ARP is it's own different thing.Will ignore for now.
		pass
	#IPV6
	if 'IPV6' in packet:
		print("IP Source Address: "+packet.ipv6.src)
		print("IP Destination Address: "+packet.ipv6.dst)
		print("IP Protocol Number: "+packet.ipv6.nxt)
		#Since ports are the layer 4 address, all protocols will have TCP or UDP so...
		if 'TCP' in packet:
			print("TCP Source Port: "+packet.tcp.srcport)
			print("TCP Destination Port: "+packet.tcp.dstport)
		if 'UDP' in packet:
			print("UDP Source Port: "+packet.udp.srcport)
			print("UDP Destination Port: "+packet.udp.dstport)
	#IPV4
	if 'IP' in packet:
		print("IP Source Address: "+packet.ip.src)
		print("IP Destination Address: "+packet.ip.dst)
		print("IP Protocol Number: "+packet.ip.proto)
		#Since ports are the layer 4 address, all protocols will have TCP or UDP so...
		if 'TCP' in packet:
			print("TCP Source Port: "+packet.tcp.srcport)
			print("TCP Source Port: "+packet.tcp.dstport)
		if 'UDP' in packet:
			print("UDP Source Port: "+packet.udp.srcport)
			print("UDP Source Port: "+packet.udp.dstport)
		#Things that do not have an ip source address
		if 'ICMP' in packet:
			#ICMP has no port numbers.
			#We already have its addresses
			pass
	
