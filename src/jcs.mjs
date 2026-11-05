// RFC 8785 JSON Canonicalization Scheme, for plain JSON values (what JSON.parse returns).
//
// Every level is canonicalized: object keys sorted by UTF-16 code units (RFC 8785
// 3.2.3), no whitespace, ES2015 number and string serialization (3.2.2). Passing a key
// list to JSON.stringify is NOT this: it drops nested fields whose names aren't in the
// list, which is how the Dataplane's manifest signature came to skip nested content.

export function canonicalize(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("JCS: numbers must be finite");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalize).join(",") + "]";
  }
  if (typeof value === "object") {
    const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(value[k])).join(",") + "}";
  }
  throw new TypeError(`JCS: cannot canonicalize a ${typeof value}`);
}
