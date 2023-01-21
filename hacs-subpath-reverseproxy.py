#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler,HTTPServer
import argparse, os, random, sys, requests

from socketserver import ThreadingMixIn
import socket
import re
import traceback
import binascii 
import select
from urllib.parse import urlparse, urlsplit, parse_qsl

import time
import logging
import os

LOGLEVEL = os.environ.get('LOGLEVEL', 'INFO').upper()
LOGFORMAT = '%(asctime)s %(levelname)s %(threadName)s %(message)s'
logging.basicConfig(level=LOGLEVEL, format=LOGFORMAT)

log = logging.getLogger("")

args = None
ENCODING = 'UTF-8'

def merge_two_dicts(x, y):
    return x | y

def default_headers():
    headers = {
        'Host': '',#args.upstream
        'accept-encoding': ''
    }

    return headers

def replace_ha_strings(body):
    # sub ( patt, repl, string )
    patterns = {
        r'/api/',
        r'/auth/',
        r'/frontend_',
        r'/local/',
        r'/static/',
        r'/service_worker.js',
        r'/manifest.json',
    }
    quote_patterns = {
        r'/lovelace',
        r'/energy',
        r'/map',
        r'/config',
        r'/profile',
        r'/history',
        r'/media-browser',
    }
    for pattern in patterns:
        body = re.sub(pattern,      args.webroot + pattern, body)
    for pattern in quote_patterns:
        body = re.sub(r'"'+pattern, r'"' + args.webroot + pattern, body)
    return body

def apply_webroot(body):
    body_is_bytes = isinstance(body, bytes)
    try:
        if body_is_bytes:
            body = body.decode(ENCODING)
        body = replace_ha_strings(body)
        #reencode after
        if body_is_bytes:
            body = body.encode(encoding=ENCODING)
    except AttributeError:
        body = replace_ha_strings(body)
        pass
    except UnicodeDecodeError:
        pass
    return body

class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    # websocket support
    protocol_version = 'HTTP/1.1'

    def do_HEAD(self):
        self.do_GET(body=False)
        return
        
    def do_GET(self, body=True):
        sent = False
        try:
            url = '{}{}'.format(args.upstream.lower(), self.path)
            req_header = self.parse_headers()

            if "upgrade" in req_header and req_header['upgrade'] == "websocket":
                u = urlsplit(url)
                scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
                if netloc.find(':') == -1:
                    if scheme == "http":
                        netloc += ":80"
                    else:
                        #unsupported for now
                        raise BaseException("Unsupported")
                host, port = netloc.split(':')
                upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                upstream_sock.connect((host, int(port, 0)))
                log.debug(f"Websocket: connect to {host}:{port}")
                get=b"GET " + self.path.encode() + b" HTTP/1.1\r\n"
                upstream_sock.sendall(get)
                log.debug(f"Websocket: sending {get}")
                for hdr in req_header:
                    enchdr = hdr.encode() + b": " + req_header[hdr].encode() + b"\r\n"
                    upstream_sock.sendall(enchdr)
                    log.debug(f"Websocket: sending {enchdr}")
                upstream_sock.sendall(b"\r\n") # final blank line
                log.debug(f"Websocket: sending final blank")
                # read response and headers until the empty line and forward to the client
                line = b''
                l=b''
                response_code=None
                rep_header={}
                while l != b'\r\n':
                    line += upstream_sock.recv(4096)
                    eol = line.find(b'\n')
                    while eol != -1:
                        # pop complete line
                        l = line[:eol+1]
                        log.debug(f"Websocket: reply: {str(l)}")
                        line = line[eol+1:]
                        if l == b'\r\n':
                            break
                        if not response_code:
                            # grab response code
                            response_code = int(l.split(b' ')[1], 0)
                        else:
                            hdr=l[0:l.find(b':')]
                            val=l[l.find(b':')+2:-2]
                            rep_header[hdr.decode()]=val.decode()
                        #self.wfile.write(l)
                        eol = line.find(b'\n')
                #self.wfile.flush()
                self.send_response(response_code)
                log.debug(f"Websocket: sent code {response_code}")
                for key in rep_header:
                    if key not in ['content-length', 'Content-Length']:
                        self.send_header(key, rep_header[key])
                        log.debug(f"Websocket: sent header {key}: {rep_header[key]}")
                self.end_headers()
                # websocket mode
                selectset = [self.rfile, upstream_sock]
                while True:
                    readable, writable, exceptional = select.select(selectset, selectset, selectset)
                    if self.rfile in readable:
                        data = self.rfile.read1() # ignore buffering
                        if data and len(data) > 0:
                            log.debug(f"Websocket: client>>server {str(data)}")
                            upstream_sock.sendall(data)
                    if upstream_sock in readable:
                        data = upstream_sock.recv(4096)
                        if data and len(data) > 0:
                            log.debug(f"Websocket: server>>client {str(data)}")
                            self.wfile.write(data)
                            self.wfile.flush()
            else:
                # regular GET reverse proxying
                resp = requests.get(url, headers=merge_two_dicts(req_header, default_headers()), verify=False, stream=True)
                sent = True
                
                resp.raise_for_status()
                content = b''
                for chunk in resp.iter_content(chunk_size=8192):
                    content += chunk
                content = apply_webroot(content)
                self.send_response(resp.status_code)
                self.send_resp_headers(resp, content)
                if body:
                    self.wfile.write(content)
            return
        finally:
            if not sent:
                self.send_error(404, 'Proxy error')

    def do_POST(self, body=True):
        sent = False
        try:
            url = '{}{}'.format(args.upstream, self.path)
            req_header = self.parse_headers()
            content_len = 0
            if ('content-length' in req_header):
                content_len = int(req_header['content-length'], 0)
            post_body = self.rfile.read(content_len)

            resp = requests.post(url, data=post_body, headers=merge_two_dicts(req_header, default_headers()), verify=False, stream=True)
            sent = True
            
            content = b''
            for chunk in resp.iter_content(chunk_size=8192):
                content += chunk
            content = apply_webroot(content)
            self.send_response(resp.status_code)
            self.send_resp_headers(resp, content)
            if body:
                self.wfile.write(content)
            return
        finally:
            if not sent:
                self.send_error(404, 'Proxy error')

    def parse_headers(self):
        req_header = {}
        for name in self.headers:
            req_header[name.lower()] = self.headers[name]
        return req_header

    def send_resp_headers(self, resp, content):
        respheaders = resp.headers
        for key in respheaders:
            #'Content-Encoding', 'Transfer-Encoding', 'content-encoding', 'transfer-encoding', 
            if key not in ['content-length', 'Content-Length']:
                self.send_header(key, respheaders[key])
        self.send_header('Content-Length', len(content))
        self.end_headers()

def parse_args(argv=sys.argv[1:]):
    parser = argparse.ArgumentParser(description='Proxy HTTP requests')
    parser.add_argument('--port', dest='port', type=int, default=8124,
                        help='serve HTTP requests on specified port (default: random)')
    parser.add_argument('--upstream', dest='upstream', type=str, default='http://localhost:8123',
                        help='upstream to proxy to')
    parser.add_argument('--webroot', dest='webroot', type=str, default='/ha',
                        help='webroot for the upstream')
    args = parser.parse_args(argv)
    return args

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""
    daemon_threads = True

def main(argv=sys.argv[1:]):
    global args
    args = parse_args(argv)
    log.info(f'Proxying {args.upstream} through port {args.port}...')
    log.info(f'Apply "{args.webroot}" webroot...')
    server_address = ('0.0.0.0', args.port)
    httpd = ThreadedHTTPServer(server_address, ProxyHTTPRequestHandler)
    httpd.serve_forever()

if __name__ == '__main__':
    main()
