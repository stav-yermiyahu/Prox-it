

# Network
import socket
import select
from struct import pack, unpack
# System
from threading import Thread, activeCount
from time import sleep
from sys import exit, exc_info

#
# Configuration
#
MAX_THREADS = 200
BUFSIZE = 2048
TIMEOUT_SOCKET = 5
LOCAL_ADDR = '127.0.0.1'
LOCAL_PORT = 1080
EXIT = False

#
# Constants
#
'''Version of the protocol'''
# PROTOCOL VERSION 5
VER = '\x05'
'''Method constants'''
# '00' NO AUTHENTICATION REQUIRED
M_NOAUTH = '\x00'
# 'FF' NO ACCEPTABLE METHODS
M_NOTAVAILABLE = '\xff'
'''Command constants'''
# CONNECT '01'
CMD_CONNECT = '\x01'
'''Address type constants'''
# IP V4 address '01'
ATYP_IPV4 = '\x01'
# DOMAINNAME '03'
ATYP_DOMAINNAME = '\x03'


def error_handler(msg="", e=None):
    if msg:
        print("{} - Code: {}, Message: {}".format(msg, str(e[0]), e[1]))
    else:
        exc_type, _, exc_tb = exc_info()
        print("{}, {}".format(exc_type, exc_tb.tb_lineno))


def proxy_loop(socket_src, socket_dst):
    while not EXIT:
        try:
            reader, _, _ = select.select([socket_src, socket_dst], [], [], 1)
        except select.error:
            return
        if not reader:
            return
        try:
            for sock in reader:
                data = sock.recv(BUFSIZE)
                if not data:
                    return
                elif sock is socket_dst:
                    socket_src.send(data)
                else:
                    socket_dst.send(data)
        except socket.error as e:
            error_handler("Loop failed", e)
            return


def connect_to_dst(dst_addr, dst_port):
    try:
        s = create_socket()
        s.connect((dst_addr, dst_port))
        return s
    except socket.error as e:
        error_handler("Failed to connect to DST", e)
        return 0
    except:
        error_handler()
        return 0


def client_request(client_sock):
    try:
        # Client Request
        # +----+-----+-------+------+----------+----------+----------+
        # |VER | CMD |  RSV  | ATYP |DOMLENGTH | DST.ADDR | DST.PORT |
        # +----+-----+-------+------+----------+----------+----------+
        s5_request = client_sock.recv(BUFSIZE)
        # Verify VER, CMD and RSV
        if (s5_request[0] != VER or
                s5_request[1] != CMD_CONNECT or
                s5_request[2] != '\x00'):
            return False
        # DOMAIN NAME
        if s5_request[3] == ATYP_DOMAINNAME:
            sz_domain_name = ord(s5_request[4])
            dst_addr = s5_request[5: 5 + sz_domain_name - len(s5_request)]
            port_to_unpack = s5_request[5 + sz_domain_name:len(s5_request)]
            dst_port = unpack('>H', port_to_unpack)[0]
        else:
            return False
        return dst_addr, dst_port
    except:
        if client_sock != 0:
            client_sock.close()
        error_handler()
    return False


def request(client_sock):
    dst = client_request(client_sock)
    try:
        # Server Reply
        # +----+-----+-------+------+----------+----------+
        # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        # +----+-----+-------+------+----------+----------+
        REP = '\x07'
        BND = '\x00' + '\x00' + '\x00' + '\x00' + '\x00' + '\x00'
        if dst:
            socket_dst = connect_to_dst(dst[0], dst[1])
        if not dst or socket_dst == 0:
            REP = '\x01'
        else:
            REP = '\x00'
            BND = socket.inet_aton(socket_dst.getsockname()[0])
            BND += pack(">H", socket_dst.getsockname()[1])
        reply = VER + REP + '\x00' + ATYP_IPV4 + BND
        client_sock.sendall(reply)

        # start proxy
        if REP == '\x00':
            proxy_loop(client_sock, socket_dst)
        if client_sock != 0:
            client_sock.close()
        if socket_dst != 0:
            socket_dst.close()
    except:
        if client_sock != 0:
            client_sock.close()
        error_handler()
        return False


def get_client_greeting(client_sock):
    # Client Version identifier/method selection message
    # +----+----------+----------+
    # |VER | NMETHODS | METHODS  |
    # +----+----------+----------+
    identification_packet = client_sock.recv(BUFSIZE)
    # VER field
    if VER != identification_packet[0]:
        return M_NOTAVAILABLE
    # METHODS fields
    NMETHODS = ord(identification_packet[1])
    METHODS = identification_packet[2:]
    if (len(METHODS) != NMETHODS):
        return M_NOTAVAILABLE
    for METHOD in METHODS:
        if(METHOD == M_NOAUTH):
            return M_NOAUTH
    return M_NOTAVAILABLE


def subnegotiation(client_sock):
    try:
        METHOD = get_client_greeting(client_sock)
        # Server Method selection message
        # +----+--------+
        # |VER | METHOD |
        # +----+--------+
        reply = VER + METHOD
        client_sock.sendall(reply)
        if METHOD == M_NOAUTH:
            return True
    except:
        error_handler()
    return False


def connection(client_sock):
    if subnegotiation(client_sock):
        request(client_sock)


def create_socket():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT_SOCKET)
    except socket.error as e:
        error_handler("Failed to create socket", e)
        exit(0)
    return s


def bind_port(s):
    # Bind
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((LOCAL_ADDR, LOCAL_PORT))
    except socket.error as e:
        error_handler("Bind failed", e)
        s.close()
        exit(0)
    # Listen
    try:
        s.listen(10)
    except socket.error as e:
        error_handler("Listen failed", e)
        s.close()
        exit(0)
    return s


if __name__ == '__main__':
    new_socket = create_socket()
    bind_port(new_socket)
    while not EXIT:
        if activeCount() > MAX_THREADS:
            sleep(3)
            continue
        try:
            client_sock, addr = new_socket.accept()
            client_sock.setblocking(1)
        except:
            continue
        recv_thread = Thread(target=connection, args=(client_sock, ))
        recv_thread.start()
    new_socket.close()

