// Helper to describe wire formats

export class Wire extends DataView {
	parent = null;
	children = [];

	static minByteLength = 0;
	get maxByteLength() {
		if (this.parent) {
			const i = this.parent.children.indexOf(this) + 1;
			// If we have a parent and are not the last child, then our maxByteLength can't be greater then the byteOffset of the next item.
			if (i < this.parent.children.length) { return this.parent.children[i].byteOffset - this.byteOffset; }
			// If we have parent then our maxBytelength can't exceed the maxByteLength of our parent
			else { return this.parent.maxByteLength - (this.byteOffset - this.parent.byteOffset); }
		}
		else if (super.byteLength + this.byteOffset == this.buffer.byteLength) {
			// If we have no parent and our byteLength reaches the end of the underlying buffer, then our maxByteLength is determined by the underlying buffer
			return (this.buffer.maxByteLength ?? this.buffer.byteLength) - this.byteOffset;
		}
		else {
			// Lastly, if our byteLength doesn't reach the end of the buffer, then our maxByteLength is the same as our byteLength
			return super.byteLength;
		}
	}

	get byteLength() {
		const last_child = this.children[this.children.length - 1];
		return (last_child?.byteOffset ?? super.byteOffset) + (last_child?.byteLength ?? this.constructor.minByteLength) - super.byteOffset;
	}
	set byteLength(value) {
		// Check that the value is within [minByteLength, maxByteLength] 
		if (value < this.constructor.minByteLength || value > this.maxByteLength) throw new Error("Couldn't set the byteLength");

		const buff_byteLength = super.byteOffset + value;

		// Cascade the value to our parent (if we have one)
		if (this.parent) {
			this.parent.byteLength = (super.byteOffset - this.parent.byteOffset) + value;
		}

		// If we don't have a parent then we need to resize the buffer ourselves
		else if (buff_byteLength > super.buffer.byteLength) {
			super.buffer.resize(buff_byteLength);
		}
	}

	constructor(input, { byteOffset, byteLength, parent, setByteLength, ...values } = {}) {
		let buffer;
		if (ArrayBuffer.isView(input)) {
			byteOffset ??= input.byteOffset;
			byteLength ??= input.byteLength;
			buffer = input.buffer;
		}
		else if (input instanceof ArrayBuffer || input instanceof SharedArrayBuffer) { buffer = input; }
		else { throw new Error("The first parameter should be a buffer or buffer view."); }

		// Delete the byteLength if it matches the (current) length of the buffer anyway: The reason for this is to allow for auto resizing of the buffer later on.
		byteOffset ??= 0;
		const available = buffer.byteLength - byteOffset;
		if (!setByteLength && available < byteLength) throw new Error("Buffer can't support a wire with the given length and offset.");
		else if (available == byteLength) byteLength = undefined;

		// Create the DataView
		super(buffer, byteOffset, byteLength);

		if (!setByteLength && available < this.constructor.minByteLength) throw new Error("ByteLength isn't big enough ")

		// Trigger setters using any additional parameters
		if (parent) {
			this.parent = parent;
			this.parent.children.push(this);
		}
		if (typeof setByteLength == 'number') this.byteLength = setByteLength;
		for (const key in values) {
			this[key] = values[key];
		}

		// Detach the input wire if we are replacing it
		if (input instanceof Wire) {
			// TODO: What should happen if you manually provide a parent or children key in values?
			this.parent ??= input.parent;
			const i = (input.parent?.children ?? []).indexOf(input);
			if (i >= 0) input.parent.children[i] = this;
			input.parent = null;
		}
	}

	specialize() { return this; }

	static default_append_typ = Wire;
	append(constr = this.constructor.default_append_typ, values = null) {
		const self_byteLength = this.byteLength;
		const available = this.maxByteLength - self_byteLength;
		if (available < constr.minByteLength) return;
		
		const byteOffset = this.byteOffset + self_byteLength;
		const ret = new constr(this.buffer, { setByteLength: constr.minByteLength, ...values, byteOffset, parent: this });

		return ret;
	}

	static field(name, typ) {
		const offset = this.minByteLength;
		let byteLength;
		let get, set;

		if (name.startsWith('...')) {
			name = name.slice(3);
			Object.defineProperty(this.prototype, name, {
				get() {
					if (this.children.length == 0) {
						for (let offset = this.constructor.minByteLength; this.byteLength - offset >= typ.minByteLength;) {
							const item = new typ(this.buffer, {byteOffset: this.byteOffset + offset, parent: this});
							offset += item.byteLength;
	
							item.specialize();
						}
					}
					return this.children;
				}
			});
			this.default_append_typ = typ;
			Object.freeze(this.prototype); // Further fields cannot be added after a ...field
			return;
		}
		else if (typ == '[]') {
			Object.defineProperty(this.prototype, name, {
				get: function() {
					return new Uint8Array(this.buffer, this.byteOffset + this.constructor.minByteLength, this.byteLength - this.constructor.minByteLength);
				}
			});
			Object.freeze(this.prototype); // Further fields cannot be added after a [] field
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
			const getter = this.prototype['get' + js_typ];
			const setter = this.prototype['set' + js_typ];
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
		this.minByteLength += byteLength;
	}
}
