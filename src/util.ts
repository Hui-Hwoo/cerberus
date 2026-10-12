// Shared pure helpers: HTTP responses, JSON, hashing.
// No imports from other cerberus modules — safe to use anywhere.

/** JSON response with the right content-type. */
export function json(data: unknown, status = 200): Response {
	return new Response(JSON.stringify(data), {
		status,
		headers: { "content-type": "application/json" },
	});
}

/** Parse a JSON request body. */
export async function readJson<T>(req: Request): Promise<T> {
	return (await req.json()) as T;
}

function toHex(bytes: Uint8Array): string {
	return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** SHA-256 of a string, hex-encoded. */
export async function sha256Hex(data: string): Promise<string> {
	const digest = await crypto.subtle.digest(
		"SHA-256",
		new TextEncoder().encode(data),
	);
	return toHex(new Uint8Array(digest));
}

/** HMAC-SHA256 of a body under a key, hex-encoded (webhook signatures). */
export async function hmacSha256Hex(
	key: string,
	body: string,
): Promise<string> {
	const cryptoKey = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(key),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const sig = await crypto.subtle.sign(
		"HMAC",
		cryptoKey,
		new TextEncoder().encode(body),
	);
	return toHex(new Uint8Array(sig));
}
