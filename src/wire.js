// Helper to describe wire formats

export class Wire extends DataView {
	parent = null;
	children = [];

	static min_length = 0;
	static from(val, specialize = true) {
		let buffer, byteOffset = 0;
		if (val instanceof ArrayBuffer) { buffer = val }
		else { buffer = val.buffer; byteOffset = val.byteOffset; }

		if (typeof val.byteLength == 'number' && val.byteLength < buffer.byteLength) {
			if (val.byteLength < this.min_length) return val;
		}
		const needed = byteOffset + this.min_length;
		if (buffer.byteLength < needed) {
			if (buffer.resizable && buffer.maxByteLength >= needed) buffer.resize(needed);
			else { return val }
		}

		const ret = new this(buffer, byteOffset);
		if (val instanceof Wire) {
			ret.parent = val.parent;
			if (ret.parent) {
				const i = ret.parent.children.indexOf(val)
				ret.parent.children[i] = ret;
			}
		}

		return specialize ? ret.specialize() : ret;
	}
	specialize() { return this; }
	static field(name, typ) {
		const offset = this.min_length;
		let byteLength;
		let get, set;

		if (name == '...') {
			Object.defineProperty(this.prototype, Symbol.iterator, {
				value: function*() {
					const siblings = [];
					for (let offset = this.min_length; this.byteLength - offset >= typ.min_length;) {
						const item = new typ(this.buffer, this.byteOffset + offset);
						const align = typ.align ?? 1;
						const pad = (align - item.byteLength % align) % align;
						offset += item.byteLength + pad;

						const ret = item.specialize();
						if (!ret) continue;

						ret.parent = this;
						ret.siblings = siblings;

						yield ret;
					}
				}
			});
			return;
		}

		const arr = /^\[([1-9][0-9]*)\]$/.exec(typ);
		const num = /^([ui])(8|16|32|64)(_le)?$/i.exec(typ);
		if (arr) {
			byteLength = parseInt(arr[1]);
			get = function() {
				return new Uint8Array(this.buffer, this.byteOffset + offset, byteLength);
			};
		}
		else if (num) {
			const { 1: sign, 2: bits, 3: le_s } = num;
			const le = Boolean(le_s);
			byteLength = parseInt(bits) / 8;
			const js_typ = `${bits == '64' ? 'Big' : ''}${sign == 'u' ? 'Ui' : 'I'}nt${bits}`;
			const getter = DataView.prototype['get' + js_typ];
			const setter = DataView.prototype['set' + js_typ];
			get = function() {
				return getter.call(this, offset, le);
			};
			set = function(value) {
				setter.call(this, offset, value, le);
			};
		}
		else { throw new Error("Unknown field datatype"); }

		Object.defineProperty(this.prototype, name, {
			enumerable: true,
			get, set,
		});
		this.min_length += byteLength;
	}
}
