#!/usr/bin/python
#-*- coding: UTF-8 -*-
# Author: JiaSongsong
# Date: 2015-04-09

import sys, re, socket, threading, time, traceback
from optparse import OptionParser
from netaddr import *

DEFAULT_SERVER_PORT = 1554
TRANSPORT_TYPE_LIST = []
DEST_IP             = '127.0.0.1'
CLIENT_PORT_RANGE   = '10014-10015'
NAT_IP_PORT         = ''
ENABLE_ARQ          = False
ENABLE_FEC          = False

TRANSPORT_TYPE_MAP  = {
                        'tcp'           :   'MP2T/TCP;%s;interleaved=0-1,',
                        'tcp_over_rtp'  :   'MP2T/RTP/TCP;%s;interleaved=0-1,',
                        'udp'           :   'MP2T/UDP;%s;destination=%s;client_port=%s,',
                        'udp_over_rtp'  :   'MP2T/RTP/UDP;%s;destination=%s;client_port=%s,'
                      }

RTSP_VERSION        = 'RTSP/1.0'
DEFAULT_USERAGENT   = 'Python Rtsp Client 1.0'
HEARTBEAT_INTERVAL  = 10 # 10s

LINE_SPLIT_STR      = '\r\n'
HEADER_END_STR      = LINE_SPLIT_STR*2

CUR_RANGE           = 'npt=end-'
CUR_SCALE           = 1

#x-notice in ANNOUNCE, BOS-Begin of Stream, EOS-End of Stream
X_NOTICE_EOS,X_NOTICE_BOS,X_NOTICE_CLOSE = 2101,2102,2103

#--------------------------------------------------------------------------
# Colored Output in Console
#--------------------------------------------------------------------------
BLACK,RED,GREEN,YELLOW,BLUE,MAGENTA,CYAN,WHITE = range(90,98)
def COLOR_STR(msg,color=WHITE):
    return '\033[%dm%s\033[0m'%(color,msg)

def PRINT(msg,color=WHITE):
    sys.stdout.write(COLOR_STR(msg,color) + '\n')
#--------------------------------------------------------------------------

class RTSPClient(threading.Thread):
    def __init__(self,url):
        threading.Thread.__init__(self)
        self.setDaemon(True)
        self._recv_buf  = ''
        self._sock      = None
        self._orig_url  = url
        self._cseq      = 0
        self._session   = ''
        self._cseq_map  = {'GET_PARAMETER':0,'DESCRIBE':0,'SETUP':0,'PLAY':0,'TEARDOWN':0}
        self._server_ip,self._server_port,self._target = self._parse_url(url)
        if not self._server_ip or not self._target:
            PRINT('Invalid url: %s'%url,RED); sys.exit(1)
        self._connect_server()
        self.running    = True
        self.playing    = False
        self.location   = ''
        self.start()

    def run(self):
        try:
            while self.running:
                msg = self.recv_msg()
                if msg.startswith('RTSP'):
                    self._process_response(msg)
                elif msg.startswith('ANNOUNCE'):
                    self._process_announce(msg)
        except Exception, e:
            PRINT('Error: %s'%e,RED)
            traceback.print_exc()
        finally:
            self.running = False
            self.playing = False
            self._sock.close()

    def _parse_url(self,url):
        '''解析url,返回(ip,port,target)三元组'''
        (ip,port,target) = ('',DEFAULT_SERVER_PORT,'')
        m = re.match(r'[rtspRTSP:/]+(?P<ip>\d+\.\d+\.\d+.\d+)(:(?P<port>\d+))?(?P<target>.*)',url)
        if m is not None:
            ip      = m.group('ip')
            port    = int(m.group('port'))
            target  = m.group('target')
        #PRINT('ip: %s, port: %d, target: %s'%(ip,port,target), GREEN)
        return ip,port,target

    def _connect_server(self):
        '''连接服务器,建立socket'''
        try:
            self._sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            self._sock.connect((self._server_ip,self._server_port))
            #PRINT('Connect [%s:%d] success!'%(self._server_ip,self._server_port), GREEN)
        except socket.error, msg:
            sys.stderr.write('ERROR: %s[%s:%d]'%(msg[1],self._server_ip,self._server_port))
            traceback.print_exc()
            sys.exit(1)

    def recv_msg(self):
        '''收取一个完整响应消息或ANNOUNCE通知消息'''
        try:
            while True:
                if HEADER_END_STR in self._recv_buf: break
                more = self._sock.recv(2048)
                if not more: break
                self._recv_buf += more
        except socket.error:
            errno, errstr = sys.exc_info()[:2]
            PRINT('Receive data error: %d-%s'%(errno,errstr),RED)

        msg = ''
        if self._recv_buf:
            (msg,self._recv_buf) = self._recv_buf.split(HEADER_END_STR,1)
            content_length = self._get_content_length(msg)
            msg += HEADER_END_STR + self._recv_buf[:content_length]
            self._recv_buf = self._recv_buf[content_length:]
        return msg

    def _get_content_length(self,msg):
        '''从消息中解析Content-length'''
        m = re.search(r'[Cc]ontent-length:\s?(?P<len>\d+)',msg,re.S)
        return 0 if m is None else int(m.group('len'))

    def _process_response(self,msg):
        '''处理响应消息'''
        status,headers,body = self._parse_response(msg)
        rsp_cseq = int(headers['cseq'])
        if self._cseq_map['GET_PARAMETER'] != rsp_cseq: PRINT(msg)
        if status == 302:
            self.location = headers['location']
        if status != 200:
            self.do_teardown()
        if self._cseq_map['DESCRIBE'] == rsp_cseq:
            track_id_str = self._parse_track_id(body)
            print track_id_str
            self.do_setup(track_id_str)
        elif self._cseq_map['SETUP'] == rsp_cseq:
            self._session = headers['session']
            self.do_play(CUR_RANGE,CUR_SCALE)
        elif self._cseq_map['PLAY'] == rsp_cseq:
            self.playing = True
            self.send_heart_beat_msg()
        elif self._cseq_map['TEARDOWN'] == rsp_cseq:
            self.running = False

    def _process_announce(self,msg):
        '''处理ANNOUNCE通知消息'''
        global CUR_RANGE,CUR_SCALE
        PRINT(msg)
        headers = self._parse_header_params(msg.splitlines()[1:])
        x_notice_val = int(headers['x-notice'])
        if x_notice_val in (X_NOTICE_EOS,X_NOTICE_BOS):
            CUR_RANGE = 'npt=end-'; CUR_SCALE = 1
            self.do_play(CUR_RANGE,CUR_SCALE)
        elif x_notice_val == X_NOTICE_CLOSE:
            self.do_teardown()

    def _parse_response(self,msg):
        '''解析响应消息'''
        header,body = msg.split(HEADER_END_STR)[:2]
        header_lines = header.splitlines()
        version,status = header_lines[0].split(None,2)[:2]
        headers = self._parse_header_params(header_lines[1:])
        return int(status),headers,body

    def _parse_header_params(self,header_param_lines):
        '''解析头部参数'''
        headers = {}
        for line in header_param_lines:
            if line.strip(): # 跳过空行
                key,val = line.split(':', 1)
                headers[key.lower()] = val.strip()
        return headers

    def _parse_track_id(self,sdp):
        '''从sdp中解析trackID=2形式的字符串'''
        m = re.search(r'a=control:(?P<trackid>[\w=\d]+)',sdp,re.S)
        return '' if m is None else m.group('trackid')

    def _next_seq(self):
        self._cseq += 1
        return self._cseq

    def _sendmsg(self,method,url,headers):
        '''发送消息'''
        msg = '%s %s %s'%(method,url,RTSP_VERSION) + LINE_SPLIT_STR
        for (k,v) in headers.items():
            msg += '{0}: {1}{2}'.format(k,v,LINE_SPLIT_STR)
        if self._session:
            msg += 'Session: %s'%self._session + LINE_SPLIT_STR
        msg += 'CSeq: %d'%self._next_seq() + HEADER_END_STR        
        if method != 'GET_PARAMETER': PRINT(msg)
        try:
            self._sock.send(msg)
            self._cseq_map[method] = self._cseq
        except socket.error:
            errno, errstr = sys.exc_info()[:2]
            PRINT('Send msg error: %s'%errstr, RED)

    def _get_transport_type(self):
        '''获取SETUP时需要的Transport字符串参数'''
        transport_str = ''
        ip_type = 'unicast' if IPAddress(DEST_IP).is_unicast() else 'multicast'
        for t in TRANSPORT_TYPE_LIST:
            if t.startswith('tcp'):
                transport_str += TRANSPORT_TYPE_MAP[t]%ip_type
            else:
                transport_str += TRANSPORT_TYPE_MAP[t]%(ip_type,DEST_IP,CLIENT_PORT_RANGE)
        return transport_str

    def do_describe(self):
        headers = {}
        headers['Accept'] = 'application/sdp'
        headers['User-Agent'] = DEFAULT_USERAGENT
        if ENABLE_ARQ: headers['x-zmssRtxSdp'] = 'yes'
        if ENABLE_FEC: headers['x-zmssFecCDN'] = 'yes'
        if NAT_IP_PORT: headers['x-NAT'] = NAT_IP_PORT
        self._sendmsg('DESCRIBE',self._orig_url,headers)

    def do_setup(self,track_id_str=''):
        headers = {}
        headers['Transport'] = self._get_transport_type()
        self._sendmsg('SETUP',self._orig_url+'/'+track_id_str,headers)

    def do_play(self,range='npt=end-',scale=1):
        headers = {}
        headers['Range'] = range
        headers['Scale'] = scale
        self._sendmsg('PLAY',self._orig_url,headers)

    def do_teardown(self):
        self._sendmsg('TEARDOWN',self._orig_url,{})

    def do_options(self):
        self._sendmsg('OPTIONS',self._orig_url,{})

    def do_get_parameter(self):
        self._sendmsg('GET_PARAMETER',self._orig_url,{})

    def send_heart_beat_msg(self):
        '''定时发送GET_PARAMETER消息保活'''
        if self.running:
            self.do_get_parameter()
            threading.Timer(HEARTBEAT_INTERVAL, self.send_heart_beat_msg).start()

#-----------------------------------------------------------------------
# Input with autocompletion
#-----------------------------------------------------------------------
import readline
COMMANDS = ['play','range:','scale:','forward','backward','begin','live','teardown','exit']
def complete(text,state):
    options = [i for i in COMMANDS if i.startswith(text)]
    return options[state] if state < len(options) else None

def input_cmd():
    readline.set_completer_delims(' \t\n')
    readline.parse_and_bind("tab: complete")
    readline.set_completer(complete)
    cmd = raw_input(COLOR_STR('Input Command # ',CYAN))
    PRINT('') # add one line
    return cmd
#-----------------------------------------------------------------------

def exec_cmd(rtsp,cmd):
    '''根据命令执行操作'''
    global CUR_RANGE,CUR_SCALE
    if cmd in ('exit','teardown'):
        rtsp.do_teardown()
        return
    elif cmd == 'forward':
        if CUR_SCALE < 0: CUR_SCALE = 1
        CUR_SCALE *= 2; CUR_RANGE = 'npt=now-'
    elif cmd == 'backward':
        if CUR_SCALE > 0: CUR_SCALE = -1
        CUR_SCALE *= 2; CUR_RANGE = 'npt=now-'
    elif cmd == 'begin':
        CUR_SCALE = 1; CUR_RANGE = 'npt=beginning-'
    elif cmd == 'live':
        CUR_SCALE = 1; CUR_RANGE = 'npt=end-'
    elif cmd.startswith('play'):
        m = re.search(r'range[:\s]+(?P<range>[^\s]+)',cmd)
        if m: CUR_RANGE = m.group('range')
        m = re.search(r'scale[:\s]+(?P<scale>[\d\.]+)',cmd)
        if m: CUR_SCALE = int(m.group('scale'))

    rtsp.do_play(CUR_RANGE,CUR_SCALE)

def main(url):
    rtsp = RTSPClient(url)
    rtsp.do_describe()
    try:
        while rtsp.running or rtsp.location:
            if rtsp.playing:
                cmd = input_cmd()
                exec_cmd(rtsp,cmd)
            # 302重定向重新建链
            if not rtsp.running:
                rtsp = RTSPClient(rtsp.location)
                rtsp.do_describe()
            time.sleep(0.5)
    except KeyboardInterrupt:
        rtsp.do_teardown()
        print '\n^C received, Exit.'

if __name__ == '__main__':
    parser = OptionParser(usage='%prog [options] url')
    parser.add_option('-t','--transport',dest='transport',default='udp_over_rtp',help='Set transport type when SETUP: tcp, udp, tcp_over_rtp, udp_over_rtp[default]')
    parser.add_option('-d','--dest_ip',dest='dest_ip',help='Set dest ip of udp data transmission, default is 127.0.0.1')
    parser.add_option('-p','--client_port',dest='client_port',help='Set client port range of udp, default is "10014-10015"')
    parser.add_option('-n','--nat',dest='nat',help='Add "x-NAT" when DESCRIBE, arg format "192.168.1.100:20008"')
    parser.add_option('-r','--arq',dest='arq',action="store_true",help='Add "x-zmssRtxSdp:yes" when DESCRIBE')
    parser.add_option('-f','--fec',dest='fec',action="store_true",help='Add "x-zmssFecCDN:yes" when DESCRIBE')
    (options,args) = parser.parse_args()
    if len(args) < 1:
        parser.print_help()
        PRINT('\n  In running, you can control play by input "forward","backward","begin","live"', MAGENTA)
        PRINT('  or "play" with "range" and "scale" parameter, such as "play range:npt=beginning- scale:2"', MAGENTA)
        PRINT('  You can input "exit","teardown" or ctrl+c to quit\n', MAGENTA)
        sys.exit()

    if options.transport:   TRANSPORT_TYPE_LIST = options.transport.split(',')
    if options.dest_ip:     DEST_IP = options.dest_ip; print DEST_IP
    if options.client_port: CLIENT_PORT_RANGE = options.client_port
    if options.nat:         NAT_IP_PORT = options.nat
    if options.arq:         ENABLE_ARQ  = options.arq
    if options.fec:         ENABLE_FEC  = options.fec
    url = args[0]

    main(url)
