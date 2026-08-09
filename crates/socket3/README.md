# Extension trait for the socket2::Socket to control
- [Disable Fragmentation](https://www.ietf.org/archive/id/draft-seemann-tsvwg-udp-fragmentation-02.html)
- [Path MTU retrieval](https://www.rfc-editor.org/info/rfc3542/#section-11.4)
- [Linux SIOCOUTQ ioctl](https://www.man7.org/linux/man-pages/man7/tcp.7.html)
- [MacOs SO_NWRITE sockopt](https://stackoverflow.com/questions/595426/how-to-get-amount-of-non-ack-ed-tcp-data-for-the-socket)

Calling this crate socket3 was ambitious: There isn't a real clean overlap between MacOS and Linux here.  This is barely even good enough for my code.
