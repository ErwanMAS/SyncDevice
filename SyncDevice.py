#!/usr/bin/python
# --------------------------------------------------------------------------------------------------------
import time
import pprint
import threading
import Queue 
import sys
import os.path
import io
import re
from datetime import datetime,timedelta
import argparse
import socket
import hashlib
import struct
from   struct import pack
import md5
import select
import base64
import time
import zlib
# https://docs.python.org/2/library/struct.html
# --------------------------------------------------------------------------------------------------------
#             connection.setblocking(0) ....
#
def StartDaemon(arg):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF, 2*1014*1024)
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF, 2*1014*1024)
    server_address = ('0.0.0.0', 7070)
    print >>sys.stderr, 'starting up on %s port %s' % server_address
    sock.bind(server_address)
    sock.listen(1)
    while True:
        connection, client_address = sock.accept()
        try:
            print >>sys.stderr, 'connection from', client_address
            StartExchange(connection,arg) 
        finally:
            # Clean up the connection
            connection.close()
# --------------------------------------------------------------------------------------------------------
def StartClient(arg):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF, 2*1014*1024)
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF, 2*1014*1024)
    server_address = arg.addr.split(':')
    if len(server_address) == 1:
        server_address.add(7070)
    print >>sys.stderr, 'connecting to %s port %s' % server_address
    sock.connect(server_address)
    StartExchange(sock,arg) 
# --------------------------------------------------------------------------------------------------------
def StartExchange(netsock,arg):
    if arg.action == 'sender':
        StartExchangeSender(netsock,arg)
    if arg.action == 'receiver':
        StartExchangeReceiver(netsock,arg)
# --------------------------------------------------------------------------------------------------------
def StartExchangeSender(netsock,arg):
    t=ReadCmd(netsock)
# --------------------------------------------------------------------------------------------------------
def StartExchangeReceiver(netsock,arg):
    #
    queue_4_send_packet=Queue.Queue() 
    queue_4_received_checksum=Queue.PriorityQueue() 
    queue_4_block_writer=Queue.Queue() 
    queue_4_counters=Queue.Queue() 
    #
    state=1 
    #
    while True :
        if ( queue_4_send_packet.qsize() > 0 ) :
#            print >>sys.stderr,'we need to send some packet\n' 
            readable, writable, exceptional = select.select([],[netsock],[])
            if ( writable  ) :
                item = queue_4_send_packet.get()
                SendCmd(netsock,item) 
#                print >>sys.stderr,'send %s\n' % ( item )  
                continue 
        #
        t=ReadCmd(netsock)
        if  not t :
            return 
        #
        cmdmatch = re.search('^DEVICE ([^\s]+)\s+(\d+)\s+(\d+)\s+((ULTRA)|(STANDART))\s*$',t)
        if cmdmatch:
            localsize=DeviceSize(arg.device)
            print >>sys.stderr,'must sync from %s size %s ( blocksize %s ) mode %s to device %s ( %s) \n' % ( 
                cmdmatch.group(1) ,cmdmatch.group(2), cmdmatch.group(3) , cmdmatch.group(4) , arg.device , localsize )
            if ( localsize < int(cmdmatch.group(2)) ):
                print >>sys.stderr,'can not sync because size of %s is %s\n' % ( arg.device, DeviceSize(arg.device) ) 
                return 
            state=2
            queue_4_send_packet.put('OK DEVICE')
            syncsize=int(cmdmatch.group(2))
            arg.blocksize=int(cmdmatch.group(3))
            arg.hashmode=cmdmatch.group(4).lower()
            t = threading.Thread(target=ComputeCheckSum, args=(arg,syncsize,queue_4_received_checksum))
            t.setDaemon(True)
            t.start()
            t = threading.Thread(target=ManageCheckSum, 
                                 args=(queue_4_received_checksum,queue_4_send_packet,syncsize,arg.blocksize,queue_4_counters))
            t.setDaemon(True)
            t.start()
            t = threading.Thread(target=ManageCounters, args=(arg,queue_4_counters))
            t.setDaemon(True)
            t.start()
            t = threading.Thread(target=BlockWriter, args=(arg.device,syncsize,arg.blocksize,queue_4_block_writer,queue_4_counters))
            t.setDaemon(True)
            t.start()
            continue
        else:
            if state == 1 :
                return

        cmdmatch = re.search('^C(\d+):([^:]*):(.+)\s*$',t)
        if cmdmatch:
#            print >>sys.stderr,'reception of CKSUM at pos %s / %s:%s\n' % (cmdmatch.group(1),cmdmatch.group(2),cmdmatch.group(3))
            queue_4_received_checksum.put([0,"R",int(cmdmatch.group(1)),cmdmatch.group(2),cmdmatch.group(3)]) 
            continue

        cmdmatch = re.search('^\s*BLOCK DATA\s+COMPRESS\s+(\d+)\s+(\d+)\s*$',t)
        if cmdmatch:
            datapos=int(cmdmatch.group(1))
            datalen=int(cmdmatch.group(2))
            dataraw=ReadDataOnSocket(netsock,datalen)
            if dataraw and len(dataraw) == datalen :
                dataorig=zlib.decompress(dataraw)
                queue_4_block_writer.put(['WRT',datapos,dataorig])
                continue

        print >>sys.stderr,'issue with cmd %s\n' % (t) 
        return


# --------------------------------------------------------------------------------------------------------
def ComputeCheckSum ( arg , sync_size , queue4chksum ):
    d = open(arg.device, 'rb')
    chksum_pos = 0
#    print >>sys.stderr,'start compute CKSUM for %s during %s\n' % (arg.device,sync_size) 
    while ( chksum_pos < sync_size ):
        d.seek(chksum_pos)
        dta=d.read(arg.blocksize)
        if ( args.hashmode == 'standart' ) :
            h_md5 = base64.b64encode(hashlib.md5(dta).digest())
            h_sha1 = base64.b64encode(hashlib.sha1(dta).digest())
        if ( args.hashmode == 'ultra' ) :
            h_md5 = base64.b64encode(pack('I',zlib.adler32(dta)  &  0xffffffff ))
            h_sha1 = 'X'

#        print >>sys.stderr,'compute of CKSUM at pos %s / %s:%s\n' % (chksum_pos,h_md5,h_sha1)
        queue4chksum.put([1,"L",chksum_pos,h_md5,h_sha1]) 
        chksum_pos=chksum_pos+arg.blocksize
        if queue4chksum.qsize() > 100 :
            time.sleep(3)


# --------------------------------------------------------------------------------------------------------
def ManageCheckSum ( queue4chksum , queue4sendcmd,syncsize , blocksize,queue4counters):
    last_cur_pos_ok=-blocksize 
    maxlocal=-blocksize
    maxremote=-blocksize
    cntok=0
    cntko=0
    localchksum={}
    remotechksum={}
    lastts = time.time()
    queue4counters.put([['syncsize',syncsize],['blocksize',blocksize],['cntok',0],['cntko',0],['last_cur_pos_ok',0],['cntrcvko',0]])
    while ( True ) :
        C=queue4chksum.get()
        curts=time.time()
#        if ( curts - lastts ) > 10 :
#            lastts=curts
#            print >>sys.stderr,'last_cur_pos_ok %s over syncsize %s ( %6.3f %% ) [ %9d OK / %9d KO ]' % ( last_cur_pos_ok ,syncsize,last_cur_pos_ok*100.0/syncsize ,cntok , cntko )
#        print >>sys.stderr,'we must manage this info %s , %s , %s \n' % ( C[1],C[2],C[3] )
        if C[1] == "L" :
            localchksum[C[2]]=[C[3],C[4]] 
            maxlocal=C[2] 
        else:
            remotechksum[C[2]]=[C[3],C[4]] 
            maxremote=C[2] 
        while ( maxremote > last_cur_pos_ok and maxlocal > last_cur_pos_ok ) :
            cmppos=(last_cur_pos_ok+blocksize)
#            print >>sys.stderr,'we must compare at %s ( max local %s max remote %s ) \n' % ( cmppos , maxlocal , maxremote ) 
#            pprint.pprint([localchksum,remotechksum])
            if remotechksum[cmppos][0] != localchksum[cmppos][0] or remotechksum[cmppos][1] != localchksum[cmppos][1]:
                queue4sendcmd.put("NEED DATA %s" % cmppos)
                cntko=cntko+1
                queue4counters.put([['last_cur_pos_ok',cmppos],['cntko',cntko]])
            else:
                queue4sendcmd.put("B%s" % cmppos)
                cntok=cntok+1
                queue4counters.put([['last_cur_pos_ok',cmppos],['cntok',cntok]])
            del remotechksum[cmppos]
            del localchksum[cmppos]
            last_cur_pos_ok=cmppos
        if ( syncsize-blocksize == last_cur_pos_ok ) :
            sys.stderr.write('[ManageCheckSum]Done Finish\n')
            return
# --------------------------------------------------------------------------------------------------------
def ManageCounters ( arg , queue4counters ):
    counters={}
    lastts  = time.time()
    firstts = time.time()
    while ( True ) :
        C=queue4counters.get()
        if (type(C[0]) is str ):
            C=[C] 
        for OC in C:
            counters[OC[0]]=OC[1]
        curts=time.time()
        if ( curts - lastts ) > 10 :
            elapsetime=curts-firstts
            sizedone= (counters['cntok']+counters['cntrcvko'])*counters['blocksize']
            
            sys.stderr.write('last_cur_pos_ok %14s over syncsize %14s ( %6.3f %% ) [ %9d OK / %9d KO ]' % ( counters['last_cur_pos_ok'] ,counters['syncsize'],counters['last_cur_pos_ok']*100.0/counters['syncsize'] ,counters['cntok'] , counters['cntko'] ))
            sys.stderr.write('sizeok %14s over syncsize %14s ( %6.3f %% ) curt %8d ttf %8d \n' % ( sizedone ,counters['syncsize'],sizedone*100.0/counters['syncsize'],elapsetime,
                                                                                                   int((elapsetime/(sizedone*1.0/counters['syncsize']))*(1-sizedone*1.0/counters['syncsize']))))
            lastts=curts
        if ( counters['syncsize'] - counters['blocksize'] == counters['last_cur_pos_ok'] ) :
            sys.stderr.write('[ManageCounters]Done Finish\n')
            return
# --------------------------------------------------------------------------------------------------------
def BlockWriter ( dev , syncsize , bs , queue2read ,queue4counters ):
    f = open(dev, 'rb+') 
    last_write=0 
    cntrcvko=0
    while  ( last_write < syncsize -bs ) :
        item=queue2read.get()
        if item[0] == 'WRT':
#            print >>sys.stderr,'write some data at %s ( %s) \n' % (item[1],len(item[2]))
            f.seek(item[1])
            f.write(item[2])
            last_write=item[1]
            cntrcvko=cntrcvko+1
            queue4counters.put(['cntrcvko',cntrcvko]) 
# --------------------------------------------------------------------------------------------------------
def DeviceSize ( dev ):
    try:
        f = open(dev, 'r')
        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.close()
        return size
    except:
        return -1 
# --------------------------------------------------------------------------------------------------------
def ReadDataOnSocket(netsock,lentoread):
    p=netsock.recv(lentoread)
    if len(p) == 0 :
        return 
    d=p
    while len(d) < lentoread:
        need2read=lentoread-len(d)
        p=netsock.recv(need2read)
        if len(p) == 0 :
            return 
        d=d+p
    return d
# --------------------------------------------------------------------------------------------------------
def ReadCmd(netsock):
    data=ReadDataOnSocket(netsock,4)
    if len(data) == 4:
#        pprint.pprint(data)
        cmdlen=int("0x"+data[1:4], 16)
        cmdtxt=ReadDataOnSocket(netsock,cmdlen)
#        print >>sys.stderr,'cmdrecv %s' % (cmdtxt)
        if len(cmdtxt)==cmdlen :
            return cmdtxt
    return 
# --------------------------------------------------------------------------------------------------------
def SendCmd(netsock,cmdtxt):
    cmdlen=len(cmdtxt) 
    datatosend="C%03x%s" % (cmdlen,cmdtxt)
    if netsock.sendall(datatosend):
        return 1
    return 
# --------------------------------------------------------------------------------------------------------
def benchmark_hash(arg):
    d = open(arg.device, 'rb')
    chksum_pos = 0
    nb_chksum=10
    while ( nb_chksum > 0 ) :
        d.seek(nb_chksum*arg.blocksize)
        dta=d.read(arg.blocksize)
        if ( arg.benchmark == 'md5') :
            h_b64 = base64.b64encode(hashlib.md5(dta).digest())
        if ( arg.benchmark == 'sha1') :
            h_b64 = base64.b64encode(hashlib.sha1(dta).digest())
        if ( arg.benchmark == 'adl') :
            h_b64 = base64.b64encode(pack('I',zlib.adler32(dta)  &  0xffffffff ))
        print '%02d : %-64s'% ( nb_chksum , h_b64 )
        nb_chksum-=1
    nb_chksum=200
    while ( nb_chksum > 0 ) :
        d.seek(nb_chksum*arg.blocksize)
        dta=d.read(arg.blocksize)
        if ( arg.benchmark == 'md5') :
            h_b64 = base64.b64encode(hashlib.md5(dta).digest())
        if ( arg.benchmark == 'sha1') :
            h_b64 = base64.b64encode(hashlib.sha1(dta).digest())
        if ( arg.benchmark == 'adl') :
            h_b64 = base64.b64encode(pack('I',zlib.adler32(dta)  &  0xffffffff ))
        nb_chksum-=1
    print 'end loop of 200'
# --------------------------------------------------------------------------------------------------------
parser = argparse.ArgumentParser(description="SyncDevice ( transfert a a device over the netwoek )\n." +
                                 "Typical usage , copy a vm\n") 
parser.add_argument('--mode'         ,choices=['daemon', 'client']   ,help="daemon/client , listening or not",default='client')
parser.add_argument('--action'       ,choices=['sender', 'receiver'] ,help="sender/receiver",default='receiver')
parser.add_argument('--hashmode'     ,choices=['standart', 'ultra'] ,help="checksum quality",default='standart')
parser.add_argument('--blocksize'    ,metavar='BLOCSIZE',help="size of block for transfert",default=1024*1024)
parser.add_argument('--device'       ,metavar='DISK',help="on which device",required=True)
parser.add_argument('--addr'         ,help="daemon addr")
parser.add_argument('--benchmark'    ,choices=['md5','adl','sha1'],help="benchmark of hash")
args = parser.parse_args()
# --------------------------------------------------------------------------------------------------------
if args.benchmark :
    benchmark_hash(args)
    exit()
if args.mode == 'daemon' :
    StartDaemon(args) 
if args.mode == 'client' :
    if args.addr and args.device : 
        StartClient(args) 
    else:
        print "Error no --addr" 
# --------------------------------------------------------------------------------------------------------
# 
# 
#     h = hashlib.md5(line).hexdigest()
# #    h = hashlib.sha1(line).hexdigest()
# #    h = hashlib.sha256(line).hexdigest()
# #    h = hashlib.sha512(line).hexdigest()
# # Bind the socket to the port
# # --------------------------------------------------------------------------------------------------------
# 
# #------------------------------------------------------------------------
# CXXX : commande de XXX caracteres 
# 
# #------------------------------------------------------------------------
# DEVICE <remote device> <lengths byte> <blocksize> (ULTRA|FAST|SECURE) <local device> <local offset>
# 
# C <pos> <digest1> <digest2>
# B <pos> OK
# NEED DATA <pos>
# 
# BLOCK DATA <pos>
# BLOCK DATA COMPRESS <pos> <compressed size>
# 
# #----
# 
# 
# 
# #----
# 
# CKSUM PARTIAL <pos> <size> <digest1> <digest2>
# BLOCK PARTIAL <pos> <partial size> OK
# NEED DATA PARTIAL <pos> <partial size> 
# 
# BLOCK DATA PARTIAL <pos> <partial size>
# BLOCK DATA PARTIAL COMPRESS <pos> <partial size>
# 
# #------------------------------------------------------------------------
# 
# 
# 
# 
# 
# --------------------------------------------------------------------------------------------------------

# --------------------------------------------------------------------------------------------------------
def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False
    return True
# --------------------------------------------------------------------------------------------------------
def is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True
# --------------------------------------------------------------------------------------------------------
