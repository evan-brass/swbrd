const res = Deno.dlopen(new URL('./wrapper', import.meta.url), {});

console.log(res);
