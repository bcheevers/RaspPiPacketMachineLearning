import pandas as pd
import numpy as np
import pyshark
import sys
import warnings
from sklearn import metrics
from sklearn import tree
from pandas.api.types import is_string_dtype, is_numeric_dtype
import os
from pathlib import Path

import IPython
import graphviz
import re
from sklearn.tree import export_graphviz

def createPacketFileLocation():
	Path(os.path.dirname(os.path.realpath(__file__))+"\PacketFiles").mkdir(parents=True, exist_ok=True)
def fix_missing(df,col,name):
	if is_numeric_dtype(col):
		if pd.isnull(col).sum():
			df[name+'_na'] = pd.isnull(col)
		df[name]= col.fillna(col.median())
def numericalize(df,col,name,max_n_cat):
	if not is_numeric_dtype(col) and (max_n_cat is None or col.nunique()>max_n_cat):
		df[name] = col.cat.codes+1
def train_cats(df_raw):
	df= df_raw
	for n,c in df.items():
		if is_string_dtype(c): df[n] = c.astype('category')
		#if c is object: df[n] = c.astype('category')
	
	#This function cleans the data.
	#The isTest parameter determines if the dataframe will return a field with the dependent variable 
def proc_df(df,y_fld,isTest, skip_flds=None, do_scale=False, preproc_fn=None, max_n_cat=None,subset=None):
	if not skip_flds: skip_flds=[]
	df = df.copy()
	#Keep a copy with correct prediction results
	if isTest:withY = df.copy()
	if preproc_fn: preproc_fn(df)
	y = df[y_fld].values
	df.drop(skip_flds+[y_fld], axis=1,inplace=True)
	#Fix missing/incorrect data and use category codes.
	for n,c in df.items(): fix_missing(df,c,n)
	for n,c in df.items(): numericalize(df,c,n,max_n_cat)
	res = [pd.get_dummies(df,dummy_na=True),y]
	if not do_scale: return res
	if isTest:return res,withY
	return res

def ObtainData(filename,ddosStatus):
	# Obtain the data: Timestamp,SourceIP,SourcePort,DestinationIP,DestinationPort,Protocol,DDOS?
	#Calculate Mean Packets Per Second per
	cap = pyshark.FileCapture(filename)

	packetFileData=[]
	for packet in cap:
		packetData=[]
		#Length of packet in bytes
		packetData.append(packet.sniff_time)

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
			
		#IPV6
		if 'IPV6' in packet:
			packetData.append(packet.ipv6.src)
			packetData.append(0)
			packetData.append(packet.ipv6.dst)
			packetData.append(0)
			packetData.append(packet.ipv6.nxt)
			packetData.append(0)
			#Since ports are the layer 4 address, all protocols will have TCP or UDP so...
			if 'TCP' in packet:
				packetData.append(packet.tcp.srcport)
				packetData.append(0)
				packetData.append(packet.tcp.dstport)
				packetData.append(0)
				
			if 'UDP' in packet:
				packetData.append(packet.udp.srcport)
				packetData.append(0)
				packetData.append(packet.udp.dstport)
				packetData.append(0)
			if hasattr(packet, 'icmpv6'):
				#ICMP has no port numbers.
				#We already have its addresses
				
				packetData.append(None)
				packetData.append(1)
				packetData.append(None)
				packetData.append(1)
			if 'IGMP' in packet:
				packetData.append(packet[packet.transport_layer].srcport)
				packetData.append(0)
				packetData.append(packet[packet.transport_layer].dstport)
				packetData.append(1)
		#IPV4
		if 'IP' in packet:
			packetData.append(packet.ip.src)
			packetData.append(0)
			packetData.append(packet.ip.dst)
			packetData.append(0)
			packetData.append(packet.ip.proto)
			packetData.append(0)
			#Since ports are the layer 4 address, all protocols will have TCP or UDP so...
			if 'TCP' in packet:
				packetData.append(packet.tcp.srcport)
				packetData.append(0)
				packetData.append(packet.tcp.dstport)
				packetData.append(0)
			if 'UDP' in packet:
				packetData.append(packet.udp.srcport)
				packetData.append(0)
				packetData.append(packet.udp.dstport)
				packetData.append(0)
			#Things that do not have an ip source address
			if 'ICMP' in packet:
				#ICMP has no port numbers.
				#We already have its addresses
				packetData.append(None)
				packetData.append(1)
				packetData.append(None)
				packetData.append(1)
			if 'IGMP' in packet:
				packetData.append(None)
				packetData.append(1)
				packetData.append(None)
				packetData.append(1)
		if ddosStatus ==False:
			packetData.append(False)
			packetFileData.append(packetData)
		else:
			packetData.append(True)
			packetFileData.append(packetData)
		packetData.append(int(packet.length))
	df = pd.DataFrame(packetFileData,columns=['Timestamp', 'SourceIP', 'SourceIP_na','DestinationIP', 'DestinationIP_na',
											  'Protocol', 'Protocol_na', 'SourcePort', 'SourcePort_na',
											'DestinationPort', 'DestinationPort_na',  'DDOS', 'Size'])
	return df

def CalculateMeanPacketsPerSecond(df):
	#Calculate Packets per Second (PerSec)
	lastRow=(df.tail(1))
	endTime=lastRow['Timestamp']
	firstRow=(df.head(1))
	firstTime=firstRow['Timestamp']
	# Need the total number of seconds passed.
	
	#This try except exists because sometimes we get empty numpy arrays.
	try:
		sniffTime = (endTime.values[0]-firstTime.values[0])
	except:
		sniffTime = 0
	#Count the number of packets with same Source,Destination addresses and same Source,Destination ports and protocol
	cols = ['SourceIP', 'SourcePort', 'DestinationIP', 'DestinationPort', 'Protocol']
	df['PerSec'] = df.groupby(cols)['SourceIP'].transform('count')
	#Remove NaN values caused by ARP in perSec column
	df['PerSec'].fillna(0, inplace=True)
	#Calculate Per Second
	df['PerSec'] = df['PerSec'].div(pd.Timedelta(sniffTime).total_seconds())
	return df
def validateFiles():
	# Loop through Chosen Directory.
	os.path.dirname(os.path.realpath(__file__)) + "\PacketFiles"
	fileNames = [f for f in os.listdir(os.path.dirname(os.path.realpath(__file__)) + "\PacketFiles") if
				 os.path.isfile(os.path.join(os.path.dirname(os.path.realpath(__file__)) + "\PacketFiles", f))]
	print("Files Detected: " + str(fileNames))
	# Ensure files are packet files
	validFiles = fileNames
	#Add Packet Capture File Types here
	validFiles = [f for f in fileNames if ".pcapng" in f or ".pcap" in f]
	print("Files Used: " + str(validFiles))
	return validFiles
def main():
	createPacketFileLocation()
	validFiles = validateFiles()
	#Determine which method to call based on name of file
	trainingDataFrames =[]
	testingDataFrames=[]
	for fileName in validFiles:
		#If file is for testing and IS a DDOS
		if "test_DDOS" in fileName:
			df =  ObtainData(os.path.dirname(os.path.realpath(__file__)) + "\PacketFiles\\"+fileName, True)
			df = CalculateMeanPacketsPerSecond(df)
			testingDataFrames.append(df)
		elif "test_" in fileName:
			df =  ObtainData(os.path.dirname(os.path.realpath(__file__)) + "\PacketFiles\\"+fileName, False)
			df = CalculateMeanPacketsPerSecond(df)
			testingDataFrames.append(df)
		#If file is DDOS
		elif "training_DDOS_" in fileName:
			df = ObtainData(os.path.dirname(os.path.realpath(__file__)) + "\PacketFiles\\"+fileName, True)
			df = CalculateMeanPacketsPerSecond(df)
			trainingDataFrames.append(df)
		#File is not test or ddos so must be normal traffic
		elif "training_":
			df = ObtainData(os.path.dirname(os.path.realpath(__file__)) + "\PacketFiles\\" + fileName, False)
			df = CalculateMeanPacketsPerSecond(df)
			trainingDataFrames.append(df)
		#File is invalid, so ignore
		else:
			pass
	#Combine All Training Data
	try:
		trainingDF = pd.concat(trainingDataFrames)
	except:
		print("No Training Data Provided!")
	#Remove Dependent Var
	trainingDF, y = proc_df(cleanTrainingDF(trainingDF), 'DDOS', isTest=False)
	
	#Combine ALL Testing Data
	try:
		testingDF= pd.concat(testingDataFrames)
	except:
		print("No Testing Data Provided!")
		return
	#Remove Dependent Var
	#testData contains training data and correct answers
	testData = proc_df(cleanTestingDF(testingDF), 'DDOS', isTest=True)
	
	#Remove Timestamp
	trainingDF = trainingDF.drop('Timestamp', 1)
	#Create model
	m =tree.DecisionTreeClassifier(splitter='best')
	m.fit(trainingDF, y)
	#Remove Timestamp
	testData[0] = testData[0].drop('Timestamp', 1)
	#Predict with model
	m_predict = m.predict(testData[0])
	#Evaluate Results
	print(m_predict)
	print(testData[1])
	print("Accuracy: ", metrics.accuracy_score(m_predict, testData[1]))
	#Graph
	model_graph = tree.export_graphviz(m, out_file=None,feature_names=list(testData[0].columns.values),class_names=['Non-DDOS','DDOS'])
	model_graph = graphviz.Source(model_graph)
	model_graph.render("DecisionTree")
	
	
def cleanTrainingDF(trainingDF):
	# Explicitly convert Object columns to categories
	trainingDF['Timestamp'] = trainingDF['Timestamp'].astype('category')
	trainingDF['SourceIP'] = trainingDF['SourceIP'].astype('category')
	trainingDF['SourcePort'] = trainingDF['SourcePort'].astype('category')
	trainingDF['DestinationIP'] = trainingDF['DestinationIP'].astype('category')
	trainingDF['DestinationPort'] = trainingDF['DestinationPort'].astype('category')
	trainingDF['Protocol'] = trainingDF['Protocol'].astype('category')
	#Convert Categories
	train_cats(trainingDF)
	return trainingDF
def cleanTestingDF(testingDF):
	# Explicitly convert Object columns to categories
	testingDF['Timestamp'] = testingDF['Timestamp'].astype('category')
	testingDF['SourceIP'] = testingDF['SourceIP'].astype('category')
	testingDF['SourcePort'] = testingDF['SourcePort'].astype('category')
	testingDF['DestinationIP'] = testingDF['DestinationIP'].astype('category')
	testingDF['DestinationPort'] = testingDF['DestinationPort'].astype('category')
	testingDF['Protocol'] = testingDF['Protocol'].astype('category')
	#Convert Categories
	train_cats(testingDF)
	return testingDF
def draw_tree(t, df, size=10, ratio=0.6, precision=0):
	""" Draws a representation of a random forest in IPython.
	Parameters:
	-----------
	t: The tree you wish to draw
	df: The data used to train the tree. This is used to get the names of the features.
	"""
	s=export_graphviz(t, out_file=None, feature_names=df.columns, filled=True,
					  special_characters=True, rotate=True, precision=precision)
	return graphviz.Source(re.sub('Tree {',
	   f'Tree {{ size={size}; ratio={ratio}', s))

#Setup graphiz with filepath
os.environ["PATH"] += os.pathsep + 'C:/Program Files (x86)/Graphviz2.38/bin/'
main()
