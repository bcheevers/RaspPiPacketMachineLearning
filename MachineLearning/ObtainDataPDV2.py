import pandas as pd
import numpy as np
import pyshark
import sys
from sklearn.ensemble import RandomForestClassifier
def ObtainData():
	# Obtain the data: Timestamp,SourceIP,SourcePort,DestinationIP,DestinationPort,Protocol,DDOS?
	#Calculate Mean Packets Per Second per
	cap = pyshark.FileCapture('test1.pcap')
	counter=1
	packetFileData=[]
	for packet in cap:
		packetData=[]
		print("ID"+str(counter))
		packetData.append(counter)
		packetData.append(packet.sniff_time)
		counter+=1
		if 'ARP' in packet:
			packetData.append(None)
			packetData.append(1)
			packetData.append(None)
			packetData.append(1)
			packetData.append(None)
			packetData.append(1)
			packetData.append(None)
			packetData.append(1)
			packetData.append(None)
			packetData.append(1)
			pass
		#IPV6
		if 'IPV6' in packet:
			print("IP Source Address: "+packet.ipv6.src)
			packetData.insert(2,packet.ipv6.src)
			packetData.insert(3,0)
			print("IP Destination Address: "+packet.ipv6.dst)
			packetData.insert(6,packet.ipv6.dst)
			packetData.insert(7,0)
			print("IP Protocol Number: "+packet.ipv6.nxt)
			packetData.insert(10,packet.ipv6.nxt)
			packetData.insert(11,0)
			#Since ports are the layer 4 address, all protocols will have TCP or UDP so...
			if 'TCP' in packet:
				print("TCP Source Port: "+packet.tcp.srcport)
				packetData.insert(4,packet.tcp.srcport)
				packetData.insert(5,0)
				print("TCP Destination Port: "+packet.tcp.dstport)
				packetData.insert(8,packet.tcp.dstport)
				packetData.insert(9,0)
				
			if 'UDP' in packet:
				print("UDP Source Port: "+packet.udp.srcport)
				packetData.insert(4,packet.udp.srcport)
				packetData.insert(5,0)
				print("UDP Destination Port: "+packet.udp.dstport)
				packetData.insert(8,packet.udp.dstport)
				packetData.insert(9,0)
		#IPV4
		if 'IP' in packet:
			print("IP Source Address: "+packet.ip.src)
			packetData.insert(2,packet.ip.src)
			packetData.insert(3,0)
			print("IP Destination Address: "+packet.ip.dst)
			packetData.insert(6,packet.ip.dst)
			packetData.insert(7,0)
			print("IP Protocol Number: "+packet.ip.proto)
			packetData.insert(10,packet.ip.proto)
			packetData.insert(11,0)
			#Since ports are the layer 4 address, all protocols will have TCP or UDP so...
			if 'TCP' in packet:
				print("TCP Source Port: "+packet.tcp.srcport)
				packetData.insert(4,packet.tcp.srcport)
				packetData.insert(5,0)
				print("TCP Source Port: "+packet.tcp.dstport)
				packetData.insert(8,packet.tcp.dstport)
				packetData.insert(9,0)
			if 'UDP' in packet:
				print("UDP Source Port: "+packet.udp.srcport)
				packetData.insert(4,packet.udp.srcport)
				packetData.insert(5,0)
				print("UDP Source Port: "+packet.udp.dstport)
				packetData.insert(8,packet.udp.dstport)
				packetData.insert(9,0)
			#Things that do not have an ip source address
			if 'ICMP' in packet:
				#ICMP has no port numbers.
				#We already have its addresses
				packetData.insert(4,None)
				packetData.insert(5,1)
				packetData.insert(8,None)
				packetData.insert(9,1)
		#Not a DDOS
		packetData.append(0)
		packetFileData.append(packetData)
		
	df = pd.DataFrame(packetFileData,columns=['ID','Timestamp','SourceIP','SourceIP_na','SourcePort','SourcePort_na','DestinationIP','DestinationIP_na','DestinationPort','DestinationPort_na','Protocol','Protocol_na','DDOS'])
	df.set_index('ID',drop=True,append=False,inplace=False,verify_integrity=False)
	return df
def CalculateMeanPacketsPerSecond(df):
	lastRow=(df.tail(1))
	endTime=lastRow.iloc[0]['Timestamp']
	firstRow=(df.head(1))
	firstTime=firstRow.iloc[0]['Timestamp']
	# Need the total number of seconds passed.
	sniffTime = endTime-firstTime
	#Count the number of packets with same Source,Destination addresses and same Source,Destination ports and protocol
	#newDf=df.groupby(['SourceIP','SourcePort','DestinationIP','DestinationPort','Protocol'])
	newDf['Occur'] = df['SourceIP','SourcePort','DestinationIP','DestinationPort','Protocol'].map(df['SourceIP','SourcePort','DestinationIP','DestinationPort','Protocol'].value_counts())
	print("here")
	with pd.option_context('display.max_rows', None, 'display.max_columns', None):
		print(newDf)
	pass
df = ObtainData()
CalculateMeanPacketsPerSecond(df)
#m = RandomForestClassifier(n_jobs=-1)
#m.fit(df.drop('DDOS', axis=1), df.DDOS)
