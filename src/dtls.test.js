import { assertEquals, assertInstanceOf } from 'jsr:@std/assert';
import { decodeBase64 } from 'jsr:@std/encoding/base64';

import { Dtls, DTLS_1_0, DtlsHandshake } from './dtls.js';

// A ClientHello Handshake packet:
const packet1 = decodeBase64('Fv7/AAAAAAAAAAAAjAEAAIAAAAAAAAAAgP79pKVuTmRHDh2a77NsQw1rY8xF8Co398t8Npiz3g0wmbwAAAAWwCvAL8ypzKjACcATwArAFACcAC8ANQEAAED/AQABAAAXAAAADgAJAAYAAQAIAAcAAAsAAgEAAAoACAAGAB0AFwAYAA0AFAASBAMIBAQBBQMIBQUBCAYGAQIB');

Deno.test(function packet1_decode() {
	const t = new Dtls(packet1).specialize();

	assertInstanceOf(t, DtlsHandshake);
	assertEquals(t.typ, 22);
	assertEquals(t.version, DTLS_1_0);
	assertEquals(t.epoch, 0);
	assertEquals(t.h_typ, 1);
});
