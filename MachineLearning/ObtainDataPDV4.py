import pandas as pd
import numpy as np
import pyshark
import sys
import warnings
from sklearn.ensemble import RandomForestClassifier
from pandas.api.types import is_string_dtype, is_numeric_dtype
def fix_missing(df,col,name):
	if is_numeric_dtype(col):
		if pd.isnull(col).sum(): df[name+'_na'] = pd.isnull(col)
		df[name]= col.fillna(col.median())
def numericalize(df,col,name,max_n_cat):
	if not is_numeric_dtype(col) and (max_n_cat is None or col.nunique()>max_n_cat):
		df[name] = col.cat.codes+1
def train_cats(df_raw):
	for n,c in df.items():
		if is_string_dtype(c): df[n] = c.astype('category')
		#if c is object: df[n] = c.astype('category')
		
def proc_df(df,y_fld, skip_flds=None, do_scale=False, preproc_fn=None, max_n_cat=None,subset=None):
	if not skip_flds: skip_flds=[]
	#if subset: df = get_sample(df,subset)
	df = df.copy()
	if preproc_fn: preproc_fn(df)
	y = df[y_fld].values
	df.drop(skip_flds+[y_fld], axis=1,inplace=True)
	
	for n,c in df.items(): fix_missing(df,c,n)
	for n,c in df.items(): numericalize(df,c,n,max_n_cat)
	res = [pd.get_dummies(df,dummy_na=True),y]
	if not do_scale: return res
	return res
def format_df(df, skip_flds=None, do_scale=False, preproc_fn=None, max_n_cat=None, subset=None):
	if not skip_flds: skip_flds = []
	# if subset: df = get_sample(df,subset)
	df = df.copy()
	if preproc_fn: preproc_fn(df)
	for n, c in df.items(): fix_missing(df, c, n)
	for n, c in df.items(): numericalize(df, c, n, max_n_cat)
	res = [pd.get_dummies(df, dummy_na=True)]
	if not do_scale: return res
	return res
def ObtainData(filename,ddosStatus):
	# Obtain the data: Timestamp,SourceIP,SourcePort,DestinationIP,DestinationPort,Protocol,DDOS?
	#Calculate Mean Packets Per Second per
	cap = pyshark.FileCapture(filename)
	counter=1
	packetFileData=[]
	for packet in cap:
		packetData=[]
		packetData.append(counter)
		packetData.append(packet.sniff_time)
		#print(packet.sniff_time)
		#print(type(packet.sniff_time))
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
			packetData.insert(2,packet.ipv6.src)
			packetData.insert(3,0)
			packetData.insert(6,packet.ipv6.dst)
			packetData.insert(7,0)
			packetData.insert(10,packet.ipv6.nxt)
			packetData.insert(11,0)
			#Since ports are the layer 4 address, all protocols will have TCP or UDP so...
			if 'TCP' in packet:
				packetData.insert(4,packet.tcp.srcport)
				packetData.insert(5,0)
				packetData.insert(8,packet.tcp.dstport)
				packetData.insert(9,0)
				
			if 'UDP' in packet:
				packetData.insert(4,packet.udp.srcport)
				packetData.insert(5,0)
				packetData.insert(8,packet.udp.dstport)
				packetData.insert(9,0)
		#IPV4
		if 'IP' in packet:
			packetData.insert(2,packet.ip.src)
			packetData.insert(3,0)
			packetData.insert(6,packet.ip.dst)
			packetData.insert(7,0)
			packetData.insert(10,packet.ip.proto)
			packetData.insert(11,0)
			#Since ports are the layer 4 address, all protocols will have TCP or UDP so...
			if 'TCP' in packet:
				packetData.insert(4,packet.tcp.srcport)
				packetData.insert(5,0)
				packetData.insert(8,packet.tcp.dstport)
				packetData.insert(9,0)
			if 'UDP' in packet:
				packetData.insert(4,packet.udp.srcport)
				packetData.insert(5,0)
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
		if ddosStatus ==False:
			packetData.append(False)
			packetFileData.append(packetData)
		else:
			packetData.append(True)
			packetFileData.append(packetData)
		
	df = pd.DataFrame(packetFileData,columns=['ID','Timestamp','SourceIP','SourceIP_na','SourcePort','SourcePort_na','DestinationIP','DestinationIP_na','DestinationPort','DestinationPort_na','Protocol','Protocol_na','DDOS'])
	df.set_index('ID',drop=True,append=False,inplace=False,verify_integrity=False)
	return df


def ObtainTestData(filename):
	# Obtain the data: Timestamp,SourceIP,SourcePort,DestinationIP,DestinationPort,Protocol,DDOS?
	# Calculate Mean Packets Per Second per
	cap = pyshark.FileCapture(filename)
	counter = 1
	packetFileData = []
	for packet in cap:
		packetData = []
		packetData.append(counter)
		packetData.append(packet.sniff_time)
		counter += 1
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
		# IPV6
		if 'IPV6' in packet:
			packetData.insert(2, packet.ipv6.src)
			packetData.insert(3, 0)
			packetData.insert(6, packet.ipv6.dst)
			packetData.insert(7, 0)
			packetData.insert(10, packet.ipv6.nxt)
			packetData.insert(11, 0)
			# Since ports are the layer 4 address, all protocols will have TCP or UDP so...
			if 'TCP' in packet:
				packetData.insert(4, packet.tcp.srcport)
				packetData.insert(5, 0)
				packetData.insert(8, packet.tcp.dstport)
				packetData.insert(9, 0)
			
			if 'UDP' in packet:
				packetData.insert(4, packet.udp.srcport)
				packetData.insert(5, 0)
				packetData.insert(8, packet.udp.dstport)
				packetData.insert(9, 0)
		# IPV4
		if 'IP' in packet:
			packetData.insert(2, packet.ip.src)
			packetData.insert(3, 0)
			packetData.insert(6, packet.ip.dst)
			packetData.insert(7, 0)
			packetData.insert(10, packet.ip.proto)
			packetData.insert(11, 0)
			# Since ports are the layer 4 address, all protocols will have TCP or UDP so...
			if 'TCP' in packet:
				packetData.insert(4, packet.tcp.srcport)
				packetData.insert(5, 0)
				packetData.insert(8, packet.tcp.dstport)
				packetData.insert(9, 0)
			if 'UDP' in packet:
				packetData.insert(4, packet.udp.srcport)
				packetData.insert(5, 0)
				packetData.insert(8, packet.udp.dstport)
				packetData.insert(9, 0)
			# Things that do not have an ip source address
			if 'ICMP' in packet:
				# ICMP has no port numbers.
				# We already have its addresses
				packetData.insert(4, None)
				packetData.insert(5, 1)
				packetData.insert(8, None)
				packetData.insert(9, 1)
		packetFileData.append(packetData)
	df = pd.DataFrame(packetFileData,
					  columns=['ID', 'Timestamp', 'SourceIP', 'SourceIP_na', 'SourcePort', 'SourcePort_na',
							   'DestinationIP', 'DestinationIP_na', 'DestinationPort', 'DestinationPort_na', 'Protocol',
							   'Protocol_na'])
	df.set_index('ID', drop=True, append=False, inplace=False, verify_integrity=False)
	return df
def CalculateMeanPacketsPerSecond(df):
	lastRow=(df.tail(1))
	endTime=lastRow['Timestamp']
	firstRow=(df.head(1))
	firstTime=firstRow['Timestamp']
	# Need the total number of seconds passed.
	
	#This try except exists because sometimes we get empty numpy arrays for some reason
	try:
		sniffTime = (endTime.values[0]-firstTime.values[0])
	except:
		sniffTime = 0
	#Count the number of packets with same Source,Destination addresses and same Source,Destination ports and protocol
	#newDf=df.groupby(['SourceIP','SourcePort','DestinationIP','DestinationPort','Protocol'])
	cols = ['SourceIP', 'SourcePort', 'DestinationIP', 'DestinationPort', 'Protocol']
	df['PerSec'] = df.groupby(cols)['SourceIP'].transform('count')
	#with pd.option_context('display.max_rows', None, 'display.max_columns', None):
		#print(df)
	#Remove NaN values caused by ARP in perSec column
	df['PerSec'].fillna(0, inplace=True)
	#with pd.option_context('display.max_rows', None, 'display.max_columns', None):
		#print(df)
	#Calculate Per Second
	df['PerSec'] = df['PerSec'].div(pd.Timedelta(sniffTime).total_seconds())
	return df
#Process Normal Sample Data
df = ObtainData('test1.pcap',False)
df = CalculateMeanPacketsPerSecond(df)
#Process DDOS Sample Data
df2 = ObtainData('DDOSSampleData.pcap',True)
df2 = CalculateMeanPacketsPerSecond(df2)
frames = [df,df2]
#Concatinate dataframes together
sampleDF = pd.concat(frames)
#Explicitly convert Object collumns to categories
sampleDF['Timestamp']=sampleDF['Timestamp'].astype('category')
sampleDF['SourceIP']=sampleDF['SourceIP'].astype('category')
sampleDF['SourcePort']=sampleDF['SourcePort'].astype('category')
sampleDF['DestinationIP']=sampleDF['DestinationIP'].astype('category')
sampleDF['DestinationPort']=sampleDF['DestinationPort'].astype('category')
sampleDF['Protocol']=sampleDF['Protocol'].astype('category')
#print(sampleDF.dtypes)
train_cats(sampleDF)
#print(sampleDF.dtypes)
sampleDF, y = proc_df(sampleDF,'DDOS')
#print(sampleDF.columns)
m = RandomForestClassifier(n_jobs=-1)
m.fit(sampleDF,y)
#Test data
testDf = ObtainTestData('testingdata.pcap')
testDf = CalculateMeanPacketsPerSecond(testDf)
#Explicitly convert Object collumns to categories

testDf['Timestamp']=testDf['Timestamp'].astype('category')
testDf['SourceIP']=testDf['SourceIP'].astype('category')
testDf['SourcePort']=testDf['SourcePort'].astype('category')
testDf['DestinationIP']=testDf['DestinationIP'].astype('category')
testDf['DestinationPort']=testDf['DestinationPort'].astype('category')
testDf['Protocol']=testDf['Protocol'].astype('category')
print("Datasets:")
print(sampleDF)
print(sampleDF.dtypes)
train_cats(testDf)
testDf = format_df(testDf)
print(testDf)
print(type(testDf))
#print(testDf.dtypes)
m_predict = m.predict(testDf)
for i in range(len(testDf)):
	print("Data:%s, Predicted DDOS:%s"% (testDf[i],m_predict))

print("Score: "+str((m.score(sampleDF,y))))
