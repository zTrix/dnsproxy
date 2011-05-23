#!/usr/bin/env python2

# http://tools.ietf.org/html/rfc1035

import socket,sys,struct,getopt,threading, re
try:
    from termcolor import colored
    color_enabled = True
except:
    color_enabled = False

LINE='-------------------------'


options = {'verbose'    : False
          ,'multithread': True
          ,'cache'      : False
          ,'dns_server' : '8.8.8.8'
          ,'port'       : 53
          ,'timeout'    : 1500
          ,'block_size' : 512
          ,'conf_file'  : 'dnsproxy.conf'
          }

localrule = {}

cache = dict()
QTYPE =  {1  : 'A'
         ,2  : 'NS'
         ,5  : 'CNAME'
         ,12 : 'PTR'
         ,13 : 'HINFO'
         ,15 : 'MX'
         ,252: 'AXFR'
         ,255: 'ANY'
         }

QCLASS = {1  : 'IN'
         ,2  : 'CS'
         ,3  : 'CH'
         ,4  : 'HS'
         }

def warn(s):
    s = '[ WW ] ' + s
    if color_enabled:
        print colored(s, 'yellow')
    else:
        print s

def err(s) :
    s = '[ EE ] ' + s
    if color_enabled:
        print colored(s, 'red')
    else:
        print s

def info(s):
    s = '[ II ] ' + s
    if color_enabled:
        print colored(s, 'green')
    else:
        print s

def fit(din,l=8,ch='0'):
    """ fit the data to 8 bit width """
    return (ch*(l-len(din)))+(din)

def chr4o(ch):
    if ord(ch)<128 and ord(ch)>=32:
        return ch
    else: return '.'

def o(data):
    """ for debug output """
    print ''
    hary = map(hex, map(ord, data))
    bary = map(bin, map(ord, data))
    l = len(hary)
    for i in range(0,l,2):
        if i+1<l:
            print fit(hary[i][2:],4,' '),fit(hary[i+1][2:],4,' '),'\t',fit(bary[i][2:]),fit(bary[i+1][2:]),chr4o(data[i]),chr4o(data[i+1])
        else:
            print fit(hary[i][2:],4,' '),'\t\t',bary[i][2:],chr4o(data[i])

class myThread(threading.Thread):  # each query would be assigned a new thread to handle its request
    def __init__(self,server,resolver,addr):
        self.server=server
        self.resolver=resolver
        self.addr=addr
        threading.Thread.__init__(self)
    def run(self):
        self.server.sendto(self.resolver.reply(), self.addr)
        

class DNSResolve:
    def __init__(self, querydata):
        self.data = querydata
        if options['verbose']:
            print LINE+'query:'
            o(querydata)

    def reply(self):
        ret=''
        key=self.data[2:]
        packet = self.send_req_udp(self.data)
        if not packet or len(packet) <= 0:
            packet = self.send_req_tcp(self.data)
        ret = packet
        if options['verbose']:
            print LINE+'reply:'
            o(ret)
        return ret
    
    def filter_by_rule(self, q):
        if len(q) < 12:
            return None
        qdcount = twobyte2short(q[4:6])
        if qdcount - 1:
            return None
        pos = 12
        qlen = ord(q[pos])
        query = ''
        while qlen > 0:
            query += q[pos+1 : pos+1+qlen] + '.'
            pos  += 1 + qlen
            qlen = ord(q[pos])
        pos += 1
        rt = twobyte2short(q[pos:pos+2])
        if rt - 1:
            return None
        pos += 2
        qc = twobyte2short(q[pos:pos+2])
        pos += 2
        if qc - 1:
            return None
       
        local_key = ''
        for domain in localrule.keys():
            if re.match(domain, query[:-1]):
                local_key = domain
                break
        if not len(local_key):
            return None

        q2 = ord(q[2])
        q2 |= 0x80
        q2 &= 0x06
        reply  = q[:2] + struct.pack('B', q2) + struct.pack('B', 0)
        reply += q[4:6]     # rqcount
        reply += q[4:6]     # ancount
        reply += struct.pack('H', 0) # nscount
        reply += struct.pack('H', 0) # arcount
        reply += q[12:pos]
    
    def send_req_udp(self, pkt, host = options['dns_server'], port = 53):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ret = None
        try:
            s.sendto(pkt, (host, port))
            ret, addr = s.recvfrom(options['block_size'])
        except:
            pass
        s.close()
        return ret

    def send_req_tcp(self, pkt, host = options['dns_server'], port = 53):
        pkt = struct.pack("!H", len(pkt)) + pkt      # network(big-endian), unsigned short, RFC 1035 4.2.2
                                                # should it be len(pkt)+2
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)  # TCP 
        try:
            s.connect((host,port))
            s.send(pkt)
            reply = s.recv(options['block_size'])
        except socket.error, err:
            s.close()
            print 'tcp socket error while connecting: %s' % err
        s.close()
        return reply[2:]

def twobyte2short(twobyte):
    t = map(ord, twobyte)
    return (t[0] << 8) + t[1]

def showQuery(addr,q):
    print LINE+'query comes:\n '
    print 'from',addr,'%s bytes' % str(len(q))
    print 'ID=%s'%str(twobyte2short(q[:2]))
    q2=ord(q[2])
    q3=ord(q[3])
    print 'QR=%d, Opcode=%d, AA=%d, TC=%d, RD=%d, RA=%d, Z=%d, RCODE=%d'%(q2&0x80,q2&0x74,q2&0x04,q2&0x02,q2&1,q3&0x80,q3&0x70,q3&0x0f)
    qdcount = twobyte2short(q[4:6])
    ancount = twobyte2short(q[6:8])
    nscount = twobyte2short(q[8:10])
    arcount = twobyte2short(q[10:12])
    print 'QDCOUNT=%d, ANCOUNT=%d, NSCOUNT=%d, ARCOUNT=%d\n'%(qdcount,ancount,nscount,arcount)
    print 'questions:'
    ret=''
    pos=12
    qlen=ord(q[pos])
    while qdcount>0:
        qdcount-=1
        while qlen>0:
            ret+=q[pos+1:pos+1+qlen]+'.'
            pos=pos+1+qlen
            qlen=ord(q[pos])
        pos+=1
        rt=twobyte2short(q[pos:pos+2])
        if QTYPE.has_key(rt):
            ret+='\t'+QTYPE[rt]
        pos+=2
        qc=twobyte2short(q[pos:pos+2])
        if qc==1:
            ret+='\tIN'
        print ret
        ret=''
    print ''

def main():
    server = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)  # start server
    server.bind(('',options['port']))
    info('listening on port %d' % options['port'])
    try:
        while 1:
            data, addr = server.recvfrom(options['block_size'])
            rsver = DNSResolve(data)
            if options['verbose']:
                showQuery(addr,data)
            if options['multithread']:
                myThread(server,rsver,addr).start()   # use multi threading to send reply back
            else:
                server.sendto(rsver.reply(), addr)   # directly handle the request, which may be blocking
    except KeyboardInterrupt:
        info('user Ctrl+C caught, closing ...')
        server.close()

def parseOpt(args):
    """ parse commandline param """
    opts, args = getopt.getopt(args, 'c:', 'config=')
    for handle, value in opts:
        if handle in ('-c', '--config'):
            options['conf_file'] = value

def parseConf(file):
    try:
        f = open(file, 'r')
    except IOError:
        warn('configuration file not found: "%s"' % file)
        return
    for i in f:
        line = i.strip()
        if len(line) > 0 and not line.startswith('#') and not line.startswith(';'):
            if line.find('=') > 0:
                (name, _, value) = line.partition('=')
                name = name.strip()
                value = value.strip()
                if name in ('port', 'timeout', 'block_size'):
                    options[name] = int(value)
                elif name in ('verbose', 'cache', 'multithread'):
                    options[name] = value.lower() == 'true'
                else:
                    options[name] = value
            else:
                ary = line.split()
                if ary[0].lower() == 'localrule':
                    if len(ary) > 2:
                        localrule[ary[2]] = ary[1]
                    else:
                        warn('invalid localrule: "%s"' % line)
    f.close()
                
if __name__=='__main__':
    print ''
    parseOpt(sys.argv[1:])
    parseConf(options['conf_file'])
    if options['verbose']:
        print options
        print localrule
    main()

