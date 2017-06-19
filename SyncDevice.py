#!/usr/bin/env python3
# --------------------------------------------------------------------------------------------------------
import time
import pprint
import threading
import queue
import sys
import os.path
import io
import re
from datetime import datetime,timedelta
import argparse
import socket
import hashlib
from Crypto.Hash import MD4
from skein import skein1024,skein512,skein256
import struct
from   struct import pack
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
    print('starting up on %s port %s' % server_address, file=sys.stderr)
    sock.bind(server_address)
    sock.listen(1)
    while True:
        connection, client_address = sock.accept()
        try:
            print('connection from', client_address, file=sys.stderr)
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
        server_address.append(7070)
    server_address=tuple(server_address)
    print('connecting to %s port %s' % server_address, file=sys.stderr)
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
    # ----------------------------------------------------------------------------------------------------
    localsize=DeviceSize(arg.device)
    t_infos=[None,None,None,None]
    queue_4_checksum=queue.Queue(maxsize=2048)
    #
    cmd="DEVICE %s %s %s %s" % ( arg.device , localsize , arg.blocksize , arg.hashmode.upper() )
    res=SendCmdAndWait(netsock,cmd)
    if res != "OK DEVICE" :
        if res :
            print(' receive a non-expected msg "%s" \n' % res , file=sys.stderr)
        else:
            print(' issue during the handshake\n' , file=sys.stderr)
        return
    # ----------------------------------------------------------------------------------------------------
    print("OK SendCmdAndWait DEVICE\n",file=sys.stderr)
    #
    ev_stop=threading.Event()
    t_infos[0]=[threading.Thread(target=ComputeCheckSum, args=(ev_stop,arg,localsize,queue_4_checksum)),ev_stop]
    t_infos[0][0].setDaemon(True)
    t_infos[0][0].start()
    # ----------------------------------------------------------------------------------------------------
    sync_pos=0
    sync_length=localsize
    cnt_block_in_transit=0
    # ----------------------------------------------------------------------------------------------------
    while sync_pos < sync_length :
        readable, writable, exceptional = select.select([netsock],[],[],0)
        #-----------
        if readable :
            res=ReadCmd(netsock)
            if  not res :
                print('netsock is empty\n', file=sys.stderr)
                return
            #
            cmdmatch = re.search('^B(\d+)$',res)
            if cmdmatch:
                sync_pos=int(cmdmatch.group(1))
                cnt_block_in_transit=cnt_block_in_transit-1
                print('receive ok chksum  @ %12d ' % sync_pos , file=sys.stderr)
                continue
            cmdmatch = re.search('^NEED DATA (\d+)$',res)
            if cmdmatch:
                sync_pos=int(cmdmatch.group(1))
                cnt_block_in_transit=cnt_block_in_transit-1
                print('receive ok needdata @ %12d ' % sync_pos , file=sys.stderr)
                dta=BlockRead(arg.device,sync_pos,arg.blocksize)
                if SendCmd(netsock,"BLOCK DATA %d" % sync_pos) :
                    if netsock.sendall(dta) != None :
                        print('can not send payload data for %d ' % sync_pos , file=sys.stderr)
                        break
                else:
                    print('can not send cmd block data for %d ' % sync_pos , file=sys.stderr)
                    break
                continue
            print('receive a unknow data "%s" \n' %  res , file=sys.stderr)
            break
        else:
            if ( queue_4_checksum.qsize() > 0 and cnt_block_in_transit < 100 ) :
                readable, writable, exceptional = select.select([],[netsock],[],0)
                if ( writable  ) :
                    item = queue_4_checksum.get()
                    cmd="C%s:%s:%s" % ( item[2],item[3],item[4])
                    if not SendCmd(netsock,cmd) :
                        print('can not send cksum info for %d ' % item[2] , file=sys.stderr)
                        break
                    cnt_block_in_transit=cnt_block_in_transit+1
        #-----------
    # ----------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------

# --------------------------------------------------------------------------------------------------------
def StartExchangeReceiver(netsock,arg):
    #
    queue_4_send_packet=queue.Queue()
    queue_4_received_checksum=queue.Queue(maxsize=2048)
    queue_4_block_writer=queue.Queue(maxsize=32)
    queue_4_counters=queue.Queue(maxsize=16)
    #
    # state = 1 => waiting for DEVICE command
    #
    state=1
    end_is_normal=0
    #
    last_pos_for_chksum=-arg.blocksize
    last_pos_for_askdat=-arg.blocksize
    last_pos_for_rcvdat=-arg.blocksize
    #
    t_infos=[None,None,None,None]
    #
    while True :
        if ( queue_4_send_packet.qsize() > 0 ) :
#            print >>sys.stderr,'we need to send some packet\n' 
            readable, writable, exceptional = select.select([],[netsock],[])
            if ( writable  ) :
                item = queue_4_send_packet.get()
                if type(item) is not str:
                    if item[0]=='HD':
                        last_pos_for_chksum=item[1]
                        if ( last_pos_for_askdat == last_pos_for_rcvdat ) and queue_4_block_writer.qsize() == 0 :
                            queue_4_counters.put(['lastwritepos',last_pos_for_chksum])
                    if item[0]=='ND':
                        last_pos_for_askdat=item[1]
                    SendCmd(netsock,item[2])
                else:
                    SendCmd(netsock,item)
#                print >>sys.stderr,'send %s\n' % ( item[2] )
                continue
        #
        readable, writable, exceptional = select.select([netsock],[],[],1)
        #
        if ( not readable ) :
            if ( last_pos_for_chksum == syncsize-arg.blocksize or last_pos_for_askdat == syncsize-arg.blocksize ) :
                # we reach the end of device on our side
                if ( last_pos_for_rcvdat == last_pos_for_askdat ) :
                    end_is_normal=1
                    break
            continue
        #
        t=ReadCmd(netsock)
        if  not t :
            print('netsock is empty\n', file=sys.stderr)
            if state==1:
                return
            else:
                break
        #
        cmdmatch = re.search('^DEVICE ([^\s]+)\s+(\d+)\s+(\d+)\s+((ULTRA)|(FAST)|(STANDART)|(SECURE))\s*$',t)
        if cmdmatch:
            localsize=DeviceSize(arg.device)
            print('must sync from %s size %s ( blocksize %s ) mode %s to device %s ( %s) \n' % (
                cmdmatch.group(1) ,cmdmatch.group(2), cmdmatch.group(3) , cmdmatch.group(4) , arg.device , localsize ), file=sys.stderr)
            if ( localsize < int(cmdmatch.group(2)) ):
                print('can not sync because size of %s is %s\n' % ( arg.device, DeviceSize(arg.device) ), file=sys.stderr)
                return
            state=2
            queue_4_send_packet.put('OK DEVICE')
            syncsize=int(cmdmatch.group(2))
            arg.blocksize=int(cmdmatch.group(3))
            arg.hashmode=cmdmatch.group(4).lower()
            queue_4_counters.put([['syncsize',syncsize],['blocksize',arg.blocksize],['cntok',0],['cntko',0],['last_cur_pos_ok',-arg.blocksize],['cntrcvko',0],['lastwritepos',-arg.blocksize]])
            #-------------------------------------------------------------------------------------------------
            ev_stop=threading.Event()
            t_infos[0]=[threading.Thread(target=ComputeCheckSum, args=(ev_stop,arg,syncsize,queue_4_received_checksum)),ev_stop]
            t_infos[0][0].setDaemon(True)
            t_infos[0][0].start()
            #-------------------------------------------------------------------------------------------------
            ev_stop=threading.Event()
            t_infos[1]=[threading.Thread(target=ManageCheckSum,
                                 args=(ev_stop,queue_4_received_checksum,queue_4_send_packet,syncsize,arg.blocksize,queue_4_counters,queue_4_block_writer)),ev_stop]
            t_infos[1][0].setDaemon(True)
            t_infos[1][0].start()
            #-------------------------------------------------------------------------------------------------
            ev_stop=threading.Event()
            t_infos[2]=[threading.Thread(target=ManageCounters, args=(ev_stop,arg,queue_4_counters)),ev_stop]
            t_infos[2][0].setDaemon(True)
            t_infos[2][0].start()
            #-------------------------------------------------------------------------------------------------
            t_infos[3]=[threading.Thread(target=BlockWriter, args=(ev_stop,arg.device,syncsize,arg.blocksize,queue_4_block_writer,queue_4_counters)),ev_stop]
            t_infos[3][0].setDaemon(True)
            t_infos[3][0].start()
            #-------------------------------------------------------------------------------------------------
            continue
        else:
            if state == 1 :
                return

        cmdmatch = re.search('^C(\d+):([^:]*):(.+)\s*$',t)
        if cmdmatch:
#            print('reception of CKSUM at pos %s / %s:%s\n' % (cmdmatch.group(1),cmdmatch.group(2),cmdmatch.group(3)),file=sys.stderr)
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
                last_pos_for_rcvdat=datapos
                continue
            else:
                print('incomplete payload for cmd %s\n' % (t), file=sys.stderr)
                break

        cmdmatch = re.search('^\s*BLOCK DATA\s+(\d+)\s*$',t)
        if cmdmatch:
            datapos=int(cmdmatch.group(1))
            dataraw=ReadDataOnSocket(netsock,arg.blocksize)
            if dataraw and len(dataraw) == arg.blocksize :
                queue_4_block_writer.put(['WRT',datapos,dataraw])
                last_pos_for_rcvdat=datapos
                continue
            else:
                print('incomplete payload for cmd %s\n' % (t), file=sys.stderr)
                break

        print('issue with cmd %s\n' % (t), file=sys.stderr)
        break
    #---------------------------------------------------------
    queue_4_block_writer.put(['END'])
    t_infos[3][0].join()
    #
    if end_is_normal == 1 :
        t_infos[1][0].join()
        t_infos[0][0].join()
    #
    queue_4_counters.put(['END'])
    t_infos[2][0].join()
    #
    if end_is_normal == 0 :
        t_infos[0][1].set()
        t_infos[1][1].set()
        t_infos[1][0].join()
        t_infos[0][0].join()
    #
    print('end of sync\n', file=sys.stderr)
    exit()


# --------------------------------------------------------------------------------------------------------
def ComputeCheckSum ( stop , arg , sync_size , queue4chksum ):
    d = open(arg.device, 'rb')
    chksum_pos = 0
#    print >>sys.stderr,'start compute CKSUM for %s during %s\n' % (arg.device,sync_size)
    while ( chksum_pos < sync_size ):
        if stop.is_set():
            break
        d.seek(chksum_pos)
        dta=d.read(arg.blocksize)
        if ( args.hashmode == 'standart' ) :
            h_md5 = base64.b64encode(hashlib.md5(dta).digest())
            h_sha1 = base64.b64encode(hashlib.sha1(dta).digest())
        if ( args.hashmode == 'ultra' ) :
            h_md5 = base64.b64encode(pack('I',zlib.adler32(dta)  &  0xffffffff ))
            h_sha1 = b"X"
        if ( args.hashmode == 'fast' ) :
            h_md5 = base64.b64encode(pack('I',zlib.adler32(dta)  &  0xffffffff ))
            h=MD4.new()
            h.update(dta)
            h_sha1 = base64.b64encode(h.digest())
        if ( args.hashmode == 'secure' ) :
            h_md5 = base64.b64encode(skein1024(dta).digest())
            h_sha1 = base64.b64encode(hashlib.sha512(dta).digest())

#        print ('compute of CKSUM at pos %s / %s:%s\n' % (chksum_pos,h_md5,h_sha1),file=sys.stderr)
        queue4chksum.put([1,"L",chksum_pos,h_md5.decode(),h_sha1.decode()])
        chksum_pos=chksum_pos+arg.blocksize
    #----------------------------------------------------
    sys.stderr.write('[ComputeCheckSum]Done Finish\n')

# --------------------------------------------------------------------------------------------------------
def ManageCheckSum ( stop , queue4chksum , queue4sendcmd,syncsize , blocksize,queue4counters,queue4blockwriter):
    last_cur_pos_ok=-blocksize
    maxlocal=-blocksize
    maxremote=-blocksize
    cntok=0
    cntko=0
    localchksum={}
    remotechksum={}
    lastts = time.time()
    while ( True ) :
        try:
            C=queue4chksum.get(timeout=2)
        except:
            C=None
        if stop.is_set():
            break
        if not C :
            continue
        #
        curts=time.time()
#        if ( curts - lastts ) > 10 :
#            lastts=curts
#            print >>sys.stderr,'last_cur_pos_ok %s over syncsize %s ( %6.3f %% ) [ %9d OK / %9d KO ]' % ( last_cur_pos_ok ,syncsize,last_cur_pos_ok*100.0/syncsize ,cntok , cntko )
#        print ('we must manage this info %s , %s , %s \n' % ( C[1],C[2],C[3] ),file=sys.stderr)
        if C[1] == "L" :
            localchksum[C[2]]=[C[3],C[4]] 
            maxlocal=C[2] 
        else:
            remotechksum[C[2]]=[C[3],C[4]] 
            maxremote=C[2] 
        while ( maxremote > last_cur_pos_ok and maxlocal > last_cur_pos_ok ) :
            cmppos=(last_cur_pos_ok+blocksize)
#            print('we must compare at %s ( max local %s max remote %s ) \n' % ( cmppos , maxlocal , maxremote ) , file=sys.stderr)
#            pprint.pprint([localchksum,remotechksum])
            if remotechksum[cmppos][0] != localchksum[cmppos][0] or remotechksum[cmppos][1] != localchksum[cmppos][1]:
                queue4sendcmd.put(['ND',cmppos,"NEED DATA %s" % cmppos])
                cntko=cntko+1
                queue4counters.put([['last_cur_pos_ok',cmppos],['cntko',cntko]])
            else:
                queue4sendcmd.put(['HD',cmppos,"B%s" % cmppos])
                cntok=cntok+1
                queue4counters.put([['last_cur_pos_ok',cmppos],['cntok',cntok]])
            del remotechksum[cmppos]
            del localchksum[cmppos]
            last_cur_pos_ok=cmppos
        if ( syncsize-blocksize == last_cur_pos_ok ) :
            break
    #
    sys.stderr.write('[ManageCheckSum]Done Finish\n')
# --------------------------------------------------------------------------------------------------------
def DisplayCounters ( countervals , elapstime ):
    last_pos_ref=countervals['syncsize']
    last_cur_cmp=countervals['last_cur_pos_ok']+countervals['blocksize']
    last_cur_wrt=countervals['lastwritepos']+countervals['blocksize']
    per_done_wrt=last_cur_wrt*1.0/last_pos_ref
    sys.stderr.write('last_cur_pos_cmp %14s over syncsize %14s ( %6.3f %% ) [ %9d OK / %9d KO ]' % ( last_cur_cmp ,last_pos_ref,last_cur_cmp*100.0/last_pos_ref ,countervals['cntok'] , countervals['cntko'] ))
    sys.stderr.write('sizewrt %14s over syncsize %14s ( %6.3f %% ) curt %8d ttf %8d \n' % (  last_cur_wrt,last_pos_ref,per_done_wrt*100.0,elapstime,int((elapstime/max(per_done_wrt,0.001))*(1-per_done_wrt)) ) )

def ManageCounters ( stop , arg , queue4counters ):
    counters={}
    lastts  = time.time()
    firstts = time.time()
    while ( True ) :
        try:
            C=queue4counters.get(timeout=2)
        except:
            C=None
        curts=time.time()
        if C:
            if (type(C[0]) is str ) and C[0] == 'END' :
                elapsedtime=curts-firstts
                DisplayCounters(counters,elapsedtime)
                sys.stderr.write('[ManageCounters]Done Finish\n')
                return
#            pprint.pprint(C)
            if (type(C[0]) is str ):
                C=[C]
            for OC in C:
                counters[OC[0]]=OC[1]
        if ( 'syncsize' in counters and 'blocksize' in counters and 'lastwritepos' in counters and 'last_cur_pos_ok' in counters ) and ( curts - lastts ) > 4 :
            elapsedtime=curts-firstts
            DisplayCounters(counters,elapsedtime)
            lastts=curts
# --------------------------------------------------------------------------------------------------------
def BlockRead ( dev , syncpos , bs ):
    f = open(dev, 'rb')
    f.seek(syncpos)
    dta=f.read(bs)
    if len(dta) == 0 :
        return
    return dta
# --------------------------------------------------------------------------------------------------------
def BlockWriter ( stop , dev , syncsize , bs , queue2read ,queue4counters ):
    f = open(dev, 'rb+')
    last_write=0
    cntrcvko=0
    tt=0
    tv=0
    while  ( last_write < syncsize -bs ) :
        item=queue2read.get()
        if item[0] == 'WRT':
#            print >>sys.stderr,'write some data at %s ( %s) \n' % (item[1],len(item[2]))
            t1=time.time()
            f.seek(item[1])
            f.write(item[2])
            last_write=item[1]
            cntrcvko=cntrcvko+1
            #
            v=len(item[2])
            tv=tv+v
            t2=time.time()
            tt=tt+t2-t1
            mustsleep=tv*1.0/(1024*1024)-tt
            #
            if mustsleep > 0.5 :
#                print('%f secs.  %d trfs => %f'% (tt,tv,mustsleep),file=sys.stderr)
                tt=tt+mustsleep
                time.sleep(mustsleep)
            queue4counters.put([['cntrcvko',cntrcvko],['lastwritepos',last_write]])
        if item[0] == 'END':
            last_write=syncsize -bs
    sys.stderr.write('[BlockWriter]Done Finish\n')
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
    if data and len(data) == 4:
#        pprint.pprint(data)
        cmdlen=int("0x"+data[1:4].decode(), 16)
        cmdtxt=ReadDataOnSocket(netsock,cmdlen).decode()
#        print('cmdrecv %s' % (cmdtxt), file=sys.stderr)
        if len(cmdtxt)==cmdlen :
            return cmdtxt
    return
# --------------------------------------------------------------------------------------------------------
def SendCmd(netsock,cmdtxt):
    cmdlen=len(cmdtxt)
    datatosend=("C%03x%s" % (cmdlen,cmdtxt)).encode()
    if netsock.sendall(datatosend) == None :
        return 1
    return
# --------------------------------------------------------------------------------------------------------
def SendCmdAndWait(netsock,cmdtxt):
    if SendCmd(netsock,cmdtxt) :
        return ReadCmd(netsock)
    return
# --------------------------------------------------------------------------------------------------------
def benchmark_hash(arg):
    d = open(arg.device, 'rb')
    nb_chksum=200
    while ( nb_chksum > 0 ) :
        d.seek(nb_chksum*arg.blocksize)
        dta=d.read(arg.blocksize)
        if ( arg.benchmark == 'md5') :
            h_b64 = base64.b64encode(hashlib.md5(dta).digest())
        if ( arg.benchmark == 'sha1') :
            h_b64 = base64.b64encode(hashlib.sha1(dta).digest())
        if ( arg.benchmark == 'sha512') :
            h_b64 = base64.b64encode(hashlib.sha512(dta).digest())
        if ( arg.benchmark == 'adl') :
            h_b64 = base64.b64encode(pack('I',zlib.adler32(dta)  &  0xffffffff ))
        if ( arg.benchmark == 'md4') :
            h=MD4.new()
            h.update(dta)
            h_b64 = base64.b64encode(h.digest())
        if ( arg.benchmark == 'skein_1024') :
            h=skein1024(dta)
            h_b64 = base64.b64encode(h.digest())
        if ( arg.benchmark == 'skein_512') :
            h=skein512(dta)
            h_b64 = base64.b64encode(h.digest())
        if ( arg.benchmark == 'skein_256') :
            h=skein256(dta)
            h_b64 = base64.b64encode(h.digest())
        if ( nb_chksum % 50 == 0 ):
            print('# %-12s : %03d : %-64s'% ( arg.benchmark , nb_chksum , h_b64.decode() ))
        nb_chksum-=1
    print('end loop of 200')
# --------------------------------------------------------------------------------------------------------
parser = argparse.ArgumentParser(description="SyncDevice ( transfert a a device over the netwoek )\n." +
                                 "Typical usage , copy a vm\n")
parser.add_argument('--mode'         ,choices=['daemon', 'client']   ,help="daemon/client , listening or not",default='client')
parser.add_argument('--action'       ,choices=['sender', 'receiver'] ,help="sender/receiver",default='receiver')
parser.add_argument('--hashmode'     ,choices=['secure','standart', 'fast','ultra'] ,help="checksum quality",default='standart')
parser.add_argument('--blocksize'    ,metavar='BLOCSIZE',type=int,help="size of block for transfert",default=1024*1024)
parser.add_argument('--device'       ,metavar='DISK',help="on which device",required=True)
parser.add_argument('--addr'         ,help="daemon addr")
parser.add_argument('--benchmark'    ,choices=['md5','adl','sha1','sha512','md4','skein_1024','skein_512','skein_256'],help="benchmark of hash")
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
        print("Error no --addr")
# --------------------------------------------------------------------------------------------------------
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
