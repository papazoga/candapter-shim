import sys
import socket
import select
import struct
import argparse

def handle_can_data(cansock, socket_fds):
    frame = cansock.recv(32)
    can_id, length = struct.unpack('II', frame[0:8])
    data = frame[8:length+8]
    #print("got can: {:03x} {}".format(can_id, length))
    out = "t{:03x}{:1x}".format(can_id, length)
    out += ''.join( [ "{:02x}".format(x) for x in data ] )
    out += '\r'
    for s in socket_fds:
        s.send(out.encode("ascii"))

def handle_candapter_data(s, cansock, rbuf):
    msgs = [ x.strip() for x in rbuf.split(b'\r') ]

    for msg in msgs:
        if not msg: continue

        cmd = msg.decode("ascii").lower()
        #print("MSG: {}".format(cmd))
        if cmd[0] =='c':
            #print("connect")
            s.send(b'\x06')
        elif cmd[0] =='s':
            #print("set speed")
            s.send(b'\x06')
        elif cmd[0] =='o':
            #print("open can bus")
            s.send(b'\x06')
        elif cmd[0] =='t':
            #print("tx standard: {}".format(cmd[1:]))
            can_id = int(cmd[1:4],16)
            l = int(cmd[4],16)
            d = cmd[5:]
            data = []

            while d:
                data.append(int(d[0:2],16))
                d = d[2:]

            #print("data=%r,len=%d" % (data, len(data)))
            out = struct.pack("II", can_id, l) + bytes(data[0:l])
            #print("sending {}".format(out))
            cansock.send(out)
            s.send(b'\x06')
        elif cmd[0] == 'x':
            print("tx extended: {}".format(cmd[1:]))
            s.send(b'\x06')
        else:
            print("unknown: {}".format(cmd))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', '-p', dest='tcp_port', type=int, default=1111)
    parser.add_argument('--iface', '-i', dest='can_iface', type=str, default="can0")
    args = parser.parse_args()

    #print("port={}, iface={}".format(args.tcp_port, args.can_iface))

    try:
        lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        lsock.bind( ( "0.0.0.0", args.tcp_port ) )
        lsock.listen(1)
    except OSError as e:
        sys.stderr.write("ERROR: unable to bind and listen to port {}\n".format(args.tcp_port))
        raise(e)

    socket_fds = []

    cansock = socket.socket(socket.PF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
    try:
        cansock.bind( (args.can_iface, ) )
    except OSError as e:
        sys.stderr.write("ERROR: unable to bind to interface '{}'\n".format(args.can_iface))
        raise(e)

    while True:
        rfds = [ lsock, cansock ] + socket_fds
        rfds, wfds, efds = select.select( rfds, [], [], 1.0)

        if not rfds:
            continue
        if lsock in rfds:
            conn, addr = lsock.accept()
            socket_fds.append(conn)
        elif cansock in rfds:
            handle_can_data(cansock, socket_fds)
        else:
            for s in socket_fds:
                if s in rfds:
                    rbuf = s.recv(1024)
                    if not rbuf:
                        socket_fds.remove(s)
                        continue

                    handle_candapter_data(s, cansock, rbuf)

main()
