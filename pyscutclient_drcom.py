#!/usr/bin/python
#-*- coding: utf-8 -*-

__version__ = '0.1.0'

from scapy.all import *
from hashlib import md5
import argparse
import os
import time

# 从用户输入获取username password iface
parser = argparse.ArgumentParser(description='802.1x Auth Tool for SCUT')
parser.add_argument('--username', default='', help='the username, cannot be blank')
parser.add_argument('--password', default='', help='if no password is given, will be the same as username')
parser.add_argument('--iface', default='eth0', help='the network interface of ethernet, depends on your computer, default is eth0')
args = parser.parse_args()

SAVEDUMP = True  # dump pcap file

# 一些常量
EAPOL_ASF = 4
EAPOL_KEY = 3
EAPOL_LOGOFF = 2
EAPOL_START = 1
EAPOL_EAP_PACKET = 0

EAP_FAILURE = 4
EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_SUCCESS = 3
EAP_TYPE_ID = 1
EAP_TYPE_MD5 = 4

# 获取认证需要的信息
username = args.username
password = args.password
conf.iface = args.iface
MY_INTERFACE = args.iface
MY_IP = get_if_addr(MY_INTERFACE)
MY_IP_HEX = ''
for s in MY_IP.split('.'):
    MY_IP_HEX += chr(int(s))
MY_MAC = get_if_hwaddr(MY_INTERFACE)
DST_MAC = 'ff:ff:ff:ff:ff:ff'  # 到时改为由request identity数据包中获取服务器的MAC地址


pkts=[] # 捕获的包放到该列表，用于dump pcap

p_start = Ether(src=MY_MAC, dst='01:80:c2:00:00:03', type=0x888e)/EAPOL(version=1, type=1, len=0)/Padding(load='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

p_identity = Ether(src=MY_MAC, dst=DST_MAC, type=0x888e)/EAPOL(version=1, type=0, len=26)/EAP(code=2, type=1, id=1, len=26)/Raw(load=username + '\x00\x44\x61\x00\x00' + MY_IP_HEX)/Padding(load='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

p_md5 = Ether(src=MY_MAC, dst=DST_MAC, type=0x888e)/EAPOL(version=1, type=0, len=43)/EAP(code=2, type=4, id=0, len=43)/Raw(load='\x10' + 'reseverd_for_md5' + username + '\x00Da*\x00' + MY_IP_HEX)/Padding(load='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

p_logoff = Ether(src=MY_MAC, dst='01:80:c2:00:00:03', type=0x888e)/EAPOL(version=1, type=2, len=0)/Padding(load='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')


def send_start():
    print 'SCUTclient: Start.'
    sendp(p_start, verbose=0)   #静默发送

def send_identity():
    sendp(p_identity, verbose=0)
    print 'SCUTclient: Respond Identity.'

def send_md5():
    sendp(p_md5, verbose=0)
    print 'SCUTclient: Respond MD5-Challenge.'

def send_logoff():
    sendp(p_logoff, verbose=0)
    print 'SCUTclient: Logoff.'

def update_md5_packet(server_md5_info):
    p_md5 = Ether(src=MY_MAC, dst=DST_MAC, type=0x888e)/EAPOL(version=1, type=0, len=43)/EAP(code=2, type=4, id=0, len=43)/Raw(load='\x10' + md5( '\x00' + password + server_md5_info ).hexdigest() + username + '\x00Da*\x00' + MY_IP_HEX)/Padding(load='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

def sniff_handler(pkt):
    pkts.append(pkt)
    try:
        if pkt.haslayer(EAP) and (pkt[EAP].code == EAP_REQUEST) and (pkt[EAP].type == EAP_TYPE_ID):   # 避免pkt[EAP]不存在时出错
            print 'Server: Request Identity!'
            DST_MAC = pkt.src  # 把目标MAC改为服务器的MAC
            p_identity.dst = DST_MAC
            p_md5.dst = DST_MAC
            send_identity()
        elif pkt.haslayer(EAP) and (pkt[EAP].code == EAP_REQUEST) and (pkt[EAP].type == EAP_TYPE_MD5):
            print 'Server: Request MD5-Challenge!'
            server_md5_info = pkt[EAP].load[1:17]  # 提取服务器给出的16字节md5信息 第1个字节是长度要跳过
            update_md5_packet(server_md5_info)  # 使用这个信息更新md5包
            send_md5()
        elif pkt.haslayer(EAP) and (pkt[EAP].code == EAP_SUCCESS):
            print 'Server: Success.'
        elif pkt.haslayer(EAP) and (pkt[EAP].code == EAP_FAILURE):
            print 'Server: Failure.\nWill retry after 5 seconds.\n'
            time.sleep(5)
            send_start()
    except BaseException as e:  #捕获所有异常
        print 'Error:', e


if __name__ == '__main__':
    if not username:
        print '\nUsage: sudo python pyscutclient_drcom.py --username USERNAME [--password PASSWORD] [--iface IFACE]'
        exit(1)
    if not password:
        password = username
    try:
        print '\n'
        print '='*60
        print '\n    pyscutclient_drcom by 7forz\n'
        print '  Project page at https://github.com/scutclient/pyscutclient_drcom'
        print '='*60
        print '\nConfirm your MAC: %s' %MY_MAC
        print 'Confirm your IP: %s' %MY_IP
        
        send_start()
        sniff(filter="(ether proto 0x888e) and (ether host %s)" %MY_MAC, prn = sniff_handler)  # 只捕获自己的MAC的802.1x，捕获到的包给handler处理
    except KeyboardInterrupt as e:
        print e, '用户手动停止'
    finally:
        send_logoff()
        if SAVEDUMP:
            wrpcap('pyscutclient_drcom.cap', pkts)
