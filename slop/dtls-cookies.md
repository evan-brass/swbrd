1. Modern DTLS client hellos can be quite large: large enough to be fragmented.
2. OpenSSL and MbedTLS have DTLS cookie implementations, but neither supports
   fragmented client hellos
3. Implement DTLS cookies manually:
   - Must be stateless
   - Must support fragmentation by looking for and verifying the DTLS cookie in
     the first fragment of a ClientHello
   - Write zerocopy DTLS wire format structs in crates/common. Pattern these
     after the STUN/IP/UDP/ICMP ones, using full zerocopy features like using an
     repr(u16) enum for the DTLS version.
   - Must support DTLS 1.2, but must not fail/error if the client hello is for
     DTLS 1.3
4. Implement DTLS cookies into crates/dtls-proxy
   - The HMAC used for the cookies must be keyed on BOTH src and dest ip+port,
     because the dst ip+port is used as a substitute for DTLS CIDs (which are
     unfortunately not supported)
   - openssl may require DTLS cookie generate/verify callbacks, however cookie
     generation/validation should happen elsewhere: by the time openssl sees the
     client-hello its cookie needs to already have been verified: therefore the
     verification callback (if even neccessary) should be a no-op
   - Inspect DTLS packets where we don't have an existing Ssl context. Parse
     them for a ClientHello and check the cookie. Emit a DTLS Hello Verify
     Request if needed.
   - Constrain Ssl creation (Ssl::new) to only occur for packets that contain a
     DTLS client hello with a valid cookie, and also make sure to truncate the
     packet to a single dtls fragment (the one with offset 0 containing a client
     hello with a valid cookie) to make sure that no appended client hellos/etc
     are processed by openssl. This way any parsing errors in our cookie code
     cannot be exploited to bypass cookie verification.
   - After calling do_handshake on the newly created Ssl, check the Ssl state to
     ensure that it has progressed / acknowledged the client hello fragment. We
     want to make sure that openssl will reject/drop any future client hellos
     that don't match the fragment we received to be certain that our cookie
     code is not circumvented.
