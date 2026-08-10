const urls = [
	'stun:turn.evan-brass.net',
	'turn:turn.evan-brass.net',
	'turn:turn.evan-brass.net?transport=tcp',
	'turns:turn.evan-brass.net?transport=tcp',
	'turns:turn.evan-brass.net:443?transport=tcp',
	'turns:stun.evan-brass.net?transport=tcp',
	'turns:turn-4only.evan-brass.net?transport=tcp',
];

const table = document.querySelector('table#status');
function insert(new_url) {
	let i = 0;
	for (; i < table.rows.length; ++i) {
		let url = table.rows[i].cells[0].innerText;
		if (new_url < url) break;
	}
	return table.insertRow(i);
}

for (const url of urls) {
	const test = new RTCPeerConnection({
		iceServers: [{
			urls: [url],
			username: 'user', credential: 'password',
		}]
	});
	test.addEventListener('icecandidate', ({ candidate: { address, type, relatedAddress } }) => {
		if (!type || type == 'host') return;
		const row = insert(url);
		row.style = 'background-color:lightgreen';
		row.insertCell().innerText = url;
		row.insertCell().innerText = address;
		row.insertCell().innerText = type;
		row.insertCell().innerText = relatedAddress;
	});
	test.addEventListener('icecandidateerror', ({ errorCode, errorText, address }) => {
		const row = insert(url);
		row.style = 'background-color:lightcoral';
		row.insertCell().innerText = url;
		row.insertCell().innerText = errorText;
		row.insertCell().innerText = errorCode;
		row.insertCell().innerText = address;
	});
	test.createDataChannel('');
	await test.setLocalDescription();
}
