1. How to pass ICMP information through multiple proxies.
2. There are three ways of collecting ICMP information:
   - As an ICMP packet received on a TUN interface
   - As control message data on a socket's error queue
   - As error response when sending: EMSGSIZE or EMSGCONNREFUSED
3. There's only one way of sending ICMP information: as packets on a TUN
   interface: We only use sockets on the client/user side of each proxy.
4. Platform:
   - EMSGCONNREFUSED is cross platform
   - EMSGSIZE is cross platform, but retrieving the actual MTU (via IPV6_MTU
     getsockopt) isn't
   - The error queue, or TUN occur on ICMP recv: this means they could be
     stateless, but if the contents are encrypted (as in dtls-proxy) then the
     auth tag may be missing which complicates ICMP quoting.
5. The plan I've settled on is to use connected sockets to manage the ICMP
   information. This introduces state, but moves the error to on-send where we
   have plaintext/ to quote in our icmp message. This state / book keeping may
   become useful for other purposes later: rate limiting, filtering, etc.
6. In the case of turnserver, this should flatten the client allocations to a
   single Slab<socket2::Socket> containing both TCP and connected UDP sockets.
   In order to connect the socket we'll need to know the local address to bind
   to (via IP auxillary data), but that should also fix issues I've had before
   of responding to STUN requests using the wrong source address.
7. In the case of dtls-proxy, src/dst information is part of the received packet
   on the TUN interface so no special socket options are needed to get the local
   address.
8. The unconnected :3478/udp socket in turnserver should be able to handle
   binding requests. Only Allocate requests should fork a connected socket for
   that client. Refresh, etc on the unconnected socket may be race conditions
   from packets queued before the split: They should be dropped.
   - Mapped addresses (for allocate / subsequent Bindings) would be the remote
     addr on the connected socket
   - Relayed address would be the index into the slab turned into an IP+port.
     The address and port range need to be arguments and the mapping should be
     linear: first from the port range, then the ip range.
9. Since the allocations are just an established/connected socket to the client,
   I want to remove the partial writes buffer on tcp streams. We should instead
   use sockopts (SIOCOUTQ and write buffer size with a margin of error) to check
   if there's enough space before performing a write. Then writes should be
   retried in a loop until they write all of the data or else close the socket
   and log an error.
10. For turnserver the sockets will need to reuse port, and for dtls proxy the
    sockets will need to be ip transparent. Rewrite turnserver first noting
    anything you learn so that the next agent who rewrites the dtls-proxy can
    use it.
11. In addition to a Slab<socket2::Socket> you'll need a set of socket addresses
    which have been forked into a connected socket. When removing a socket, if
    it is UDP, then it should be removed from this list. I think it's acceptible
    to key this set only on client IP+Port: This only limits clients from
    reusing the same source port when making two UDP connections to the TURN
    server, which is not something I'm worried about.
