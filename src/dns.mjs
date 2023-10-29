const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', {fatal: true});

export class Dns {
	#view;
	constructor(inner = 512) {
		if (inner instanceof ArrayBuffer) {
			this.#view = new DataView(inner);
		}
		else if (inner instanceof DataView) {
			this.#view = inner;
		}
		else if (ArrayBuffer.isView(inner)) {
			this.#view = new DataView(inner.buffer, inner.byteOffset, inner.byteLength);
		}
		else if (typeof inner == 'number') {
			this.#view = new DataView(inner);
			// Random ID:
			crypto.getRandomValues(new Uint8Array(this.#view.buffer, this.#view.byteOffset, 2));
		}
	}
	get id() {
		return this.#view.getUint16(0);
	}
	get flags() {
		return this.#view.getUint16(2);
	}
	set flags(v) {
		this.#view.setUint16(2, v);
	}
	get_flag(offset, bits) {
		const mask = 2 ** bits - 1;
		return (this.flags >>> offset) & mask;
	}
	set_flag(offset, bits, v) {
		const mask = (2 ** bits - 1) << offset;
		this.flags = (this.flags & !mask) | ((v << offset) & mask);
	}
	get rcode() { return this.get_flag(0, 4); }
	set rcode(v) { this.set_flag(0, 4, v); }
	get ra() { return Boolean(this.get_flag(7, 1)); }
	get rd() { return Boolean(this.get_flag(8, 1)); }
	set rd(v) { this.set_flag(8, 1, Number(Boolean(v))); }
	get tc() { return Boolean(this.get_flag(9, 1)); }
	get aa() { return Boolean(this.get_flag(10, 1)); }
	get opcode() { return this.get_flag(11, 4); }
	set opcode(v) { this.set_flag(11, 4, v); }
	get qr() { return Boolean(this.get_flag(15, 1)); }
	set qr(v) { this.set_flag(15, 1, Number(Boolean(v))); }

	get body() {
		let offset = 12;
		const questions = [];
		let count = this.#view.getUint16(4);
		const take_u16 = () => {
			const ret = this.#view.getUint16(offset);
			offset += 2;
			return ret;
		};
		const append_labels = (offset, labels = []) => {
			const ret = [];

			const a = this.#view.getUint8(offset);
			let o = offset;
			if (a >= 64) {
				o = 0b00_111111_11111111 & this.#view.getUint16(offset);
				offset += 2;
			}
			while (1) {
				const len = this.#view.getUint8(o);
				o += 1;
				if (len == 0) break;
				if (len >= 64) return;
				const end = offset + len;
				if (end > this.#view.byteLength) return;
				labels.push(decoder.decode(new Uint8Array(this.#view.buffer, this.#view.byteOffset + offset, len)));
				offset += len;
			}
			name = labels.join('.');
	
			return name;
		};
		for (let i = 0; i < count; ++i) {
			const n = this.get_name(offset);
			if (!n) return;
			offset = n.offset;
			questions[i] = {name: n.name, type: take_u16(), class: take_u16()};
		}
		
		const answers = [];
		count = this.#view.getUint16(6);
		for (let i = 0; i < count; ++i) {
			const n = this.get_name(offset);
			if (!n) return;
			offset = n.offset;
			return {
				name: n.name,
				type: take_u16(),
				class: take_u16(),

			}
		}
		
		count = this.#view.getUint16(8);
		const name_servers = [];
		
		count = this.#view.getUint16(10);
		const others = [];

		return {questions, answers, name_servers, others};
	}
}
