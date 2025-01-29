// Helper to describe wire formats

export class Wire extends DataView {
	static minByteLength = 0;
	static defaults = {};

	constructor(input, { byteOffset, ...values } = {}) {
		let buffer;
		if (ArrayBuffer.isView(input)) {
			buffer = input.buffer;
			byteOffset ??= input.byteOffset;
		}
		else if (input instanceof ArrayBuffer || input instanceof SharedArrayBuffer) {
			buffer = input;
		}
		else {
			throw new Error("Wires can only be created from ArrayBuffers/SharedArrayBuffers or A view of a buffer.");
		}
		super(buffer, byteOffset);

		for (const [key, value] of Object.entries(values)) {
			this[key] = value;
		}
	}

	static field(name, typ) {
		const offset = this.minByteLength;
		let get, set, byteLength = 0, freeze = false;

		const arr = /^\[([1-9][0-9]*)?\]$/.exec(typ);
		const num = /^([ui])(8|16|32|64)(_le)?$/i.exec(typ);
		if (arr) {
			if (arr[1]) {
				byteLength = parseInt(arr[1]);
				get = function () {
					return new Uint8Array(this.buffer, this.byteOffset + offset, byteLength);
				};
			}
			else {
				get = function () {
					return new Uint8Array(this.buffer, this.byteOffset + offset, this.byteLength - offset);
				}
				freeze = true;
			}
			set = function (value) {
				get.call(this).set(value);
			};
		}
		else if (typ == 'u24') {
			byteLength = 3;
			get = function () {
				return (this.getUint8(offset) << 16) | this.getUint16(offset + 1);
			};
			set = function (value) {
				this.setUint8(offset, (value & 0xff0000) >> 16);
				this.setUint16(offset + 1, value & 0x00ffff);
			};
		}
		else if (num) {
			const { 1: sign, 2: bits, 3: le_s } = num;
			const le = Boolean(le_s);
			byteLength = parseInt(bits) / 8;
			const js_typ = `${bits == '64' ? 'Big' : ''}${sign == 'u' ? 'Ui' : 'I'}nt${bits}`;
			const getter = this.prototype['get' + js_typ];
			const setter = this.prototype['set' + js_typ];
			get = function () {
				return getter.call(this, offset, le);
			};
			set = function (value) {
				setter.call(this, offset, value, le);
			};
		}
		else { throw new Error("Unknown field datatype"); }

		Object.defineProperty(this.prototype, name, {
			enumerable: true,
			get, set,
		});
		this.minByteLength += byteLength;
		if (freeze) Object.freeze(this.prototype);
	}
}
