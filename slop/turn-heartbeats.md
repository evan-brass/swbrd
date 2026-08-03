1. The TURN protocol doesn't have an official heartbeat mechanism. It has a
   refresh timeout and also whatever data you send keeps the network path alive.
2. The spec talks about Binding Indiciations being used to keep a binding alive,
   but I think giving the Binding method double meaning is stupid. Instead,
   let's use refresh indications. In the stun crate's parlance this would be
   (Class::Request, Method::Shit), I've removed the deprecated label to make
   this Method accessible without warning.
3. From now on our refresh / expire plan will be as follows:
   - We will cap our refresh timeout at 4min, but will only actually expire a
     connection at 5min.
   - Every 1min we send a Refresh Indication (no attributes needed), and
     increment the refresh counter.
   - When we receive a refresh request, we clear the refresh counter.
   - When attempting to send a refresh indication, check counter. If it's 5,
     then it's been ~6min since the peer last refreshed, so cleanup the
     allocation.
   - If there's a send error (ECONNREFUSED/EHOSTUNREACH is what we hope to
     trigger with these), then cleanup the allocation.
