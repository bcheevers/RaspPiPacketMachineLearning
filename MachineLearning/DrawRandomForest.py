import pandas as pd
import numpy as np
import pyshark
import sys
import warnings
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import export_graphviz
import IPython
import graphviz
import re
from pandas.api.types import is_string_dtype, is_numeric_dtype
import os
#setup graphvis path
os.environ["PATH"] += os.pathsep + 'C:/Program Files (x86)/Graphviz2.38/bin/'
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
def ObtainData():
    # Obtain the data: Timestamp,SourceIP,SourcePort,DestinationIP,DestinationPort,Protocol,DDOS?
    #Calculate Mean Packets Per Second per
    cap = pyshark.FileCapture('QueensNetworkNormal1.pcap')
    counter=1
    packetFileData=[]
    for packet in cap:
        packetData=[]
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
    sniffTime = (endTime-firstTime)
    #Count the number of packets with same Source,Destination addresses and same Source,Destination ports and protocol
    #newDf=df.groupby(['SourceIP','SourcePort','DestinationIP','DestinationPort','Protocol'])
    cols = ['SourceIP', 'SourcePort', 'DestinationIP', 'DestinationPort', 'Protocol']
    df['PerSec'] = df.groupby(cols)['SourceIP'].transform('count')
    with pd.option_context('display.max_rows', None, 'display.max_columns', None):
        print(df)
    pass
    #Remove NaN values caused by ARP in perSec column
    df['PerSec'].fillna(0, inplace=True)
    with pd.option_context('display.max_rows', None, 'display.max_columns', None):
        print(df)
    #Calculate Per Second
    df['PerSec']=df['PerSec'].div(sniffTime.total_seconds())
    with pd.option_context('display.max_rows', None, 'display.max_columns', None):
        print(df)
    return df
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
df = ObtainData()
df = CalculateMeanPacketsPerSecond(df)
df['Timestamp']=df['Timestamp'].astype('object')
train_cats(df)
df, y = proc_df(df,'DDOS')
m = RandomForestClassifier(n_jobs=-1,oob_score=True)
m.fit(df,y)
print(df.columns)
print(df.dtypes)
print("Score: "+str((m.score(df,y))))
if hasattr(m,'oob_score_'):
	print("Out Of The Box Score: "+str(m.oob_score_))
graph=draw_tree(m.estimators_[0],df,precision=3)
graph.render("tree.pdf",view=True)