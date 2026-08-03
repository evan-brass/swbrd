1. I want to support client ip+port mobility in dtls-proxy
2. Normally this would happen through ICE, however I detest ICE with every fiber
   of my being.
3. ice-dissolve intercepts and gives success responses for all ICE checks that
   we care about which means clients can essentially change source IP+Port at
   any time.
4. That's what the dst ip CID accounts for, however currently we never
   re-connect the UDP socket when clients change ip
5. After mobility, the client's packets will start hitting dtls-proxy's TUN
   interface again, since they don't match the 4 tuple of the transparent
   socket.
6. I would like you to understand and then replicate the functionality of
   mbedtls_ssl_check_record
   (https://github.com/Mbed-TLS/mbedtls/blob/development/library/ssl_msg.c#L219)
   for these packets. Then for valid records perform reconnect the new client
   IP+port on the underlying socket.
   - I expect that this will require some amount of exporting keys etc. This is
     fine and would be neccessary infrastructure for the future when someone
     adds srtp support to the dtls context.
