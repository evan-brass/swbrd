export function reg_all(reg, s) {
	const ret = [];
	let t;
	while ((t = reg.exec(s))) ret.push(t);
	return ret;
}
