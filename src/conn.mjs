export class Sig {
	id;
	ice_ufrag;
	ice_pwd;
	candidates = [];
}

const default_rtc_config = {

};

export class Conn extends RTCPeerConnection {
	#dc;
	constructor(rtc_config = default_rtc_config) {
		super(rtc_config);

		this.#dc = this.createDatachannel('', {negotiated: true, id: 0});
	}
}
