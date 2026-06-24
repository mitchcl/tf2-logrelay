#if defined _logrelay_socket_included
 #endinput
#endif
#define _logrelay_socket_included

// Minimal Socket extension bindings (upstream socket.inc uses removed funcenum syntax).

enum SocketType {
    SOCKET_TCP = 1,
    SOCKET_UDP,
    SOCKET_RAW
};

typeset SocketErrorCB {
    function void (Handle socket, const int errorType, const int errorNum, any arg);
};

native Handle SocketCreate(SocketType protocol, SocketErrorCB efunc);
native void SocketSendTo(Handle socket, const char[] data, int size, const char[] hostname, int port);

public Extension __ext_smsock =
{
    name = "Socket",
    file = "socket.ext",
    autoload = 1,
    required = 1,
};
