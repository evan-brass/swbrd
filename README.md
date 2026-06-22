# turn.evan-brass.net
This is a free STUN / TURN server

## How to use
Adjust your WebRTC configuration to include this server:

```json
{
	"iceServers": [{
		"urls": [
			"turn:turn.evan-brass.net",
			"turn:turn.evan-brass.net?transport=tcp",
			"turns:turn.evan-brass.net:443?transport=tcp"
		],
		"username": "user",
		"credential": "password"
	}]
}
```
