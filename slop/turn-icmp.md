1. Context: ./icmp-plan.md and the previous dtls-proxy commit
2. turnserver doesn't currently emit any ICMP (write_network_icmp).
3. EMSGSIZE on a UDP socket should be returned as an ICMPv6 PTB.
   - The TURN server adds a fixed overhead of 20 (STUN) + 24 (XOR-PEER-ADDRESS
     with V6) + 4 (DATA Attribute header) bytes.
   - I don't know how to retrieve the MTU on the socket, since we connect to
     both IPv4 and IPv6 clients.
     - connected_udp in crates/common/src/socket.rs:102-118 uses the
       SocketAddrV6 for both bind/connect but I don't know if that means the
       v6_path_mtu function would still work.
   - To get the actual MTU of the PTB, take the pathmtu - IP4/6 - UDP - 48 +
     IP6 + UDP since the relay happens using IPv6.
4. Packets received for which we have no open socket (within RelayRange, but
   Slab key is unoccupied/None) should receive an ICMP port unreachable.
