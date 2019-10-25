import socks
import socket
import select
import struct
import requests
import socketserver

class proxyrotator(socketserver.ThreadingMixIn, socketserver.TCPServer):

    stopped = False
    allow_reuse_address = True

    def serve_forever(self):
        while not self.stopped:
            try:
                self.handle_request()
            except ValueError:
                pass

    def stop(self):
        try:
            self.server_close()
            self.stopped == True
            requests.head('http://127.0.0.1', proxies={'http': 'socks5://aztecrabbit:aztecrabbit@{}:{}'.format(*self.server_address)}, timeout=1)
        except requests.exceptions.ConnectTimeout:
            pass
        except requests.exceptions.ConnectionError:
            pass

class proxyrotator_handler(socketserver.StreamRequestHandler):

    def log(self, value, color='[G1]', type=1):
        self.server.liblog.log(value, color=color, type=type)

    def get_available_methods(self, n, methods=[]):
        for i in range(n):
            methods.append(ord(self.connection.recv(1)))

        return methods

    def authentication(self):
        try:
            version = ord(self.connection.recv(1))
            assert version == 1

            username_len = ord(self.connection.recv(1))
            username = self.connection.recv(username_len).decode('charmap')

            password_len = ord(self.connection.recv(1))
            password = self.connection.recv(password_len).decode('charmap')
        except: return

        if username == self.server.username and password == self.server.password:
            self.connection.sendall(struct.pack('!BB', version, 0))
            return True

        return False

    def generate_failed_reply(self, address_type, error_number):
        return struct.pack("!BBBBIH", self.server.socks_version, error_number, 0, address_type, 0, 0)

    def handler(self):
        sockets = [self.request, self.socket_server]
        timeout = 0
        while True:
            timeout += 1
            socket_io, _, errors = select.select(sockets, [], sockets, 3)
            if errors: break
            if socket_io:
                for sock in socket_io:
                    try:
                        data = sock.recv(self.server.buffer_size)
                        if not data: break
                        # SENT -> RECEIVE
                        elif sock is self.request:
                            self.socket_server.sendall(data)
                        elif sock is self.socket_server:
                            self.request.sendall(data)
                        timeout = 0
                    except: break
            if timeout == 10: break

    def handle(self):
        try:
            headers = self.connection.recv(2)
            version, nmethods = struct.unpack('!BB', headers)

            assert version == self.server.socks_version
            assert nmethods > 0
        except Exception:
            self.server.close_request(self.request)
            return

        methods = self.get_available_methods(nmethods)

        # accept only username and password auth
        if 2 not in set(methods):
            self.connection.sendall(struct.pack('!BB', self.server.socks_version, 255))
            self.server.close_request(self.request)
            return

        # send server choice
        self.connection.sendall(struct.pack('!BB', self.server.socks_version, 2))
        
        result = self.authentication()
        
        if not result:
            if result == False:
                self.log('Authentication failed', color='[R1]')
                self.connection.sendall(struct.pack('!BB', self.server.socks_version, 0xFF))
            self.server.close_request(self.request)
            return

        try:
            version, cmd, _, host_type = struct.unpack('!BBBB', self.connection.recv(4))
            assert version == self.server.socks_version
        except Exception:
            self.server.close_request(self.request)
            return

        if not host_type:
            self.server.close_request(self.request)
            return
        elif host_type == 1:
            host = socket.inet_ntoa(self.connection.recv(4))
        elif host_type == 3:
            host_length = self.connection.recv(1)[0]
            host = self.connection.recv(host_length).decode()

        port = struct.unpack('!H', self.rfile.read(2))[0]
        data = self.generate_failed_reply(host_type, 5)

        i = 0
        while i < len(self.server.proxies):
            i += 1
            try:
                with self.server.liblog.lock:
                    proxy = self.server.proxies.pop(0)
                    self.server.proxies.append(proxy)
                if cmd == 1:
                    self.socket_server = socks.socksocket()
                    self.socket_server.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]), rdns=True)
                    self.socket_server.connect((str(host), int(port)))
                    bind_address = self.socket_server.getsockname()
                else:
                    self.server.close_request(self.request)

                host = struct.unpack('!I', socket.inet_aton(bind_address[0]))[0]
                port = bind_address[1]
                data = struct.pack('!BBBBIH', self.server.socks_version, 0, 0, 1, host, port)
            except socks.GeneralProxyError:
                pass
            except socks.ProxyConnectionError:
                pass
            except IndexError:
                break
            else: break

        self.connection.sendall(data)

        if data[1] == 0 and cmd == 1:
            self.handler()
        
        try:
            self.server.close_request(self.request)
            socket_server.close()
        except: pass

'''
class proxyrotator(threading.Thread):
    def __init__(self, proxy_rotator_host_port, buffer_size = 32768):
        super(proxyrotator, self).__init__()

        self.proxy_rotator_host = str(proxy_rotator_host_port[0])
        self.proxy_rotator_port = int(proxy_rotator_host_port[1])
        self.buffer_size = buffer_size

    def log(self, value, color='[G1]'):
        log(value, color=color)

    def run(self):
        try:
            server = proxyrotator_server((self.proxy_rotator_host, self.proxy_rotator_port), proxyrotator_handler)
            server.socks_version = 5
            server.buffer_size = self.buffer_size
            server.username = 'aztecrabbit'
            server.password = 'aztecrabbit'
            server.serve_forever()
        except OSError:
            self.log('Port {} used by another programs'.format(self.proxy_rotator_port), color='[R1]')
'''