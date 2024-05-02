export class Protocol {
	#inner;
	get inner() { return this.#inner; }
	#reader;
	#writer;
	#mode;
	readable;
	writable;
	constructor(inner, { mode } = {}) {
		this.#inner = inner;
		this.writable = new WritableStream(this);
		this.type = 'bytes';
		this.readable = new ReadableStream(this);
		this.#mode = mode;
	}

	start() {
		this.#writer ??= this.#inner.writable.getWriter();
		this.#reader ??= this.#inner.readable.getReader({ mode: this.#mode });
	}

	async pull(controller) {
		const { value, done } = await this.read();
		if (value) controller.enqueue(value);
		if (done) controller.close();
	}
	read() {
		return this.#reader.read(...arguments);
	}
	async write(chunk, {map = x => x} = {}) {
		while (this.#writer.desiredSize < 0) await this.#writer.ready;
		if (this.#writer.desiredSize == null || this.#writer.desiredSize == 0) return;
		await this.#writer.write(map(chunk));
	}

	close() { return this.#writer.close(); }
	abort(reason) { return this.#writer.abort(reason); }
	cancel(reason) { return this.#reader.cancel(reason); }
}
